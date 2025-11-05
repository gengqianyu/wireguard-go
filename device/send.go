/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 * 此处根据注释，Outbound 作用是处理 tun 离开电脑的数据包，并且 Encryption 过程 跟 outbound 过程有关，所以下一步我们关注 RoutineReadFromTUN 和 RoutineEncryption。
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 * 此文件中的函数（大致）按照处理数据包的顺序出现。
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 *
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)

 * 锁机制、生产者与消费者

 * 每个节点（peer）的数据包顺序 必须保持不变，但 数据包 的加密过程是 乱序进行的：
 * 顺序消费者会尝试获取锁；
 * 工作线程 在完成数据包的处理（加密）后，会释放锁。

 * 若数据元素被插入到 “加密队列”（encryption queue）中，其内容前面会附带足够的 “冗余数据”（junk）以容纳传输层头部（transport header），从而支持就地构建传输层消息。
 */

type QueueOutboundElement struct {
	buffer  *[MaxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "buffer" (always!)
	nonce   uint64                // nonce for encryption
	keypair *Keypair              // keypair for encryption
	peer    *Peer                 // related peer
}

type QueueOutboundElementsContainer struct {
	sync.Mutex
	elems []*QueueOutboundElement
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetMessageBuffer()
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() {
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
		default:
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	peer.SendStagedPackets()
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
	}

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	packet := make([]byte, MessageInitiationSize)
	_ = msg.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	packet := make([]byte, MessageResponseSize)
	_ = response.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	reply, err := device.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}

	packet := make([]byte, MessageCookieReplySize)
	_ = reply.marshal(packet)
	// TODO: allocation could be avoided
	device.net.bind.Send([][]byte{packet}, initiatingElem.endpoint)

	return nil
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > RekeyAfterTime) {
		peer.SendHandshakeInitiation(false)
	}
}

// 它实现了从 TUN 虚拟网络设备 读取本地应用程序发出的 IP 数据包，
// 并将这些数据包 准备好 发送到对应的 WireGuard 对等节点。
// 它连接了 本地网络栈 和 WireGuard 的加密传输层，是整个 VPN 隧道中 数据流 出本地系统 的第一个处理点。
// 与 Inbound 流量处理 不同，因为 OutBind 流量 是要发送给对应的 peer endpoint 的，
// 每个 peer 都有一个对应的 outbound queue，和各自的加密 keypair
// 因此 负责进一步加工发送数据的是 对应的 peer 结构体，不是 device 结构体。
func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Verbosef("Routine: TUN reader - stopped")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader - started")

	// 批量处理准备：根据 BatchSize() 初始化批量处理所需的缓冲区和数据结构
	var (
		batchSize   = device.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		bufs        = make([][]byte, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       = 0
		sizes       = make([]int, batchSize)
		offset      = MessageTransportHeaderSize
	)

	for i := range elems {
		elems[i] = device.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	// 对象池管理：使用 defer 确保函数退出时 归还所有消息缓冲区和出站元素 到对象池，避免内存泄漏
	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
		}
	}()

	// 	Device加工（加密处理）

	// WireGuard设备接收到TUN设备传来的数据包后，会进行以下处理：
	// 根据目标IP确定对应的对等节点(Peer)
	// 获取当前的加密密钥对(Keypair)
	// 以下两步是在各自的 peer 中完成的
	// 使用ChaCha20-Poly1305算法加密数据包
	// 添加WireGuard头部信息

	for {
		// read packets 批量读取：从 TUN 设备一次性读取多个数据包以提高效率
		count, readErr = device.tun.device.Read(bufs, sizes, offset)
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue //数据包过滤：跳过无效（大小小于1）的数据包
			}

			elem := elems[i]
			elem.packet = bufs[i][offset : offset+sizes[i]]

			// lookup peer
			var peer *Peer

			// IP 版本识别：通过 检查数据包 第一个字节的高 4 位来区分 IPv4 和 IPv6 数据包
			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				// 目标地址提取：根据 IP 版本提取对应的目标 IP 地址
				dst := elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]

				// Peer 查找：使用 allowedips.Lookup() 根据 目标 IP 地址 找到对应的 Peer
				peer = device.allowedips.Lookup(dst)

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				dst := elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
				peer = device.allowedips.Lookup(dst)

			default:
				device.log.Verbosef("Received packet with unknown IP version")
			}

			// 无效 Peer 处理：跳过未找到对应 Peer 的数据包
			if peer == nil {
				continue
			}
			// 按 Peer 分组：将属于同一个 Peer 的 数据包 收集到同一个容器中
			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = device.NewOutboundElement()

			// 资源重用：为每个已处理的出站元素重新创建新的元素，以便重用缓冲区
			bufs[i] = elems[i].buffer[:]
		}

		// 数据包发送
		for peer, elemsForPeer := range elemsByPeer {
			// 运行状态检查：只处理处于运行状态的 Peer 的数据包
			if peer.isRunning.Load() {
				// 数据包暂存：调用 StagePackets() 将数据包放入 Peer 的暂存队列
				peer.StagePackets(elemsForPeer)

				// 数据包发送：调用 SendStagedPackets() 触发数据包的实际发送过程
				peer.SendStagedPackets()
			} else {
				// 资源回收：对于非运行状态的 Peer，直接归还其相关资源到对象池
				for _, elem := range elemsForPeer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}

			// 清理映射：处理完成后从映射中删除 Peer 条目
			delete(elemsByPeer, peer)
		}

		// 错误处理
		if readErr != nil {
			// 可恢复错误：对于 ErrTooManySegments 这类非致命错误，记录日志后继续执行
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				device.log.Verbosef("Dropped some packets from multi-segment read: %v", readErr)
				continue
			}
			// 致命错误处理：对于其他错误，如果设备未关闭，则记录错误并触发设备关闭流程
			if !device.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
				}
				go device.Close()
			}
			return
		}
	}
}

func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	for {
		select {
		case peer.queue.staged <- elems:
			return
		default:
		}
		select {
		case tooOld := <-peer.queue.staged:
			for _, elem := range tooOld.elems {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(tooOld)
		default:
		}
	}
}

// 负责处理已经暂存在队列中的数据包，为它们 分配加密参数 并最终发送。
// 这个函数是 WireGuard 数据发送路径中的关键环节，连接了 数据包暂存 和 实际加密发送 的过程。
func (peer *Peer) SendStagedPackets() {
top:
	// 队列检查：首先检查暂存队列是否为空，为空则直接返回
	// 设备状态检查：检查设备是否处于启动状态(isUp())，如果设备未启动则不发送任何数据包
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	// 密钥对状态检查

	// 获取当前密钥对：获取 Peer 当前使用的加密密钥对
	keypair := peer.keypairs.Current()

	// 如果没有可用密钥对 (keypair == nil)
	// 或者发送的 nonce 数量已达到限制 (keypair.sendNonce.Load() >= RejectAfterMessages)
	// 或者密钥对已过期 (time.Since(keypair.created) >= RejectAfterTime)
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= RejectAfterTime {
		// 发握手：当上述任一条件满足时，调用 SendHandshakeInitiation(false) 发起新的握手来获取或更新密钥对
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer

		// 非阻塞接收：使用带 default 的 select 实现非阻塞地 从暂存队列接收数据包容器
		select {
		case elemsContainer := <-peer.queue.staged:
			i := 0
			for _, elem := range elemsContainer.elems {
				// 设置 elem.peer 指向当前 Peer
				elem.peer = peer

				// 通过原子操作 keypair.sendNonce.Add(1) - 1 为每个数据包分配唯一的 nonce 值
				elem.nonce = keypair.sendNonce.Add(1) - 1

				// nonce 超限处理
				// 当 nonce 超过限制时，将这些数据包单独收集到 elemsContainerOOO 容器中
				if elem.nonce >= RejectAfterMessages {
					// 将 sendNonce 锁定 在限制值 RejectAfterMessages
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					// 有效数据包重排：对于有效的数据包，重新组织在原容器中，移除无效包
					elemsContainer.elems[i] = elem
					i++
				}
				// 设置 elem.keypair 指向当前使用的密钥对
				elem.keypair = keypair
			}

			elemsContainer.Lock()                           //容器加锁：在修改容器内容前加锁，确保线程安全
			elemsContainer.elems = elemsContainer.elems[:i] //截断容器：根据有效数据包数量 重新设置容器大小

			// 超限包重新暂存：对于 nonce 超限的数据包，调用 StagePackets 将它们重新放入暂存队列（注释说明了这可能导致包的顺序混乱）
			if elemsContainerOOO != nil {
				peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			// 空容器处理：如果处理后容器为空，则 归还容器资源 并跳转到 top 重新检查条件
			if len(elemsContainer.elems) == 0 {
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			// add to parallel and sequential queue
			// Peer 状态检查：检查 Peer 是否仍在运行
			if peer.isRunning.Load() {
				// 正常发送路径：如果 Peer 运行正常，将 数据包容器 同时发送到两个队列：
				// peer.queue.outbound.c：Peer 特定的出站队列
				// peer.device.queue.encryption.c：设备级的加密队列
				peer.queue.outbound.c <- elemsContainer
				peer.device.queue.encryption.c <- elemsContainer

				// 这里的操作正好对应 receive.go 中的 device.RoutineReceiveIncoming 里的 InBound 入栈流量操作

			} else {
				// 资源回收路径：如果 Peer 已不再运行，则归还所有相关资源到对象池
				for _, elem := range elemsContainer.elems {
					peer.device.PutMessageBuffer(elem.buffer)
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}

			// 重新处理标记：如果存在重新暂存的超限包，跳转到 top 重新检查条件
			if elemsContainerOOO != nil {
				goto top
			}
		default:
			return
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elemsContainer := <-peer.queue.staged:
			for _, elem := range elemsContainer.elems {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption(id int) {
	var paddingZeros [PaddingMultiple]byte
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	for elemsContainer := range device.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			// populate header fields
			header := elem.buffer[:MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, MessageTransportType)
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			// pad content to multiple of 16
			paddingSize := calculatePaddingSize(len(elem.packet), int(device.tun.mtu.Load()))
			elem.packet = append(elem.packet, paddingZeros[:paddingSize]...)

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				header,
				nonce[:],
				elem.packet,
				nil,
			)
		}
		elemsContainer.Unlock()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.outbound.c {
		bufs = bufs[:0]
		if elemsContainer == nil {
			return
		}
		if !peer.isRunning.Load() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and SendBuffers code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
			device.PutOutboundElementsContainer(elemsContainer)
			continue
		}
		dataSent := false
		elemsContainer.Lock()
		for _, elem := range elemsContainer.elems {
			if len(elem.packet) != MessageKeepaliveSize {
				dataSent = true
			}
			bufs = append(bufs, elem.packet)
		}

		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		err := peer.SendBuffers(bufs)
		if dataSent {
			peer.timersDataSent()
		}
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		device.PutOutboundElementsContainer(elemsContainer)
		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			if errors.As(err, &errGSO) {
				device.log.Verbosef(err.Error())
				err = errGSO.RetryErr
			}
		}
		if err != nil {
			device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
			continue
		}

		peer.keepKeyFreshSending()
	}
}
