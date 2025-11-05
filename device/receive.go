/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint conn.Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	buffer   *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
}

type QueueInboundElementsContainer struct {
	sync.Mutex
	elems []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */

// 负责 接收和解包 传入的 WireGuard 数据包，并根据 数据包类型 分发到不同的处理队列。
// 这个函数通常以 goroutine 形式运行，是 WireGuard 协议栈中处理入站流量的第一道关卡。
func (device *Device) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.log.Verbosef("Routine: receive incoming %s - started", recvName)

	// receive datagrams until conn is closed

	// 初始化用于批量接收数据包的缓冲区数组，并从设备的缓冲区池中获取内存，避免频繁的内存分配和 GC。
	var (
		bufsArrs    = make([]*[MaxMessageSize]byte, maxBatchSize)
		bufs        = make([][]byte, maxBatchSize)
		err         error
		sizes       = make([]int, maxBatchSize)
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
	)

	// 批量处理优化 函数使用批量接收和处理机制，通过 maxBatchSize 参数控制一次处理的数据包数量，显著提高了处理效率，减少了系统调用次数。
	// 内存池化管理 通过 GetMessageBuffer 和 PutMessageBuffer 方法从设备的内存池中获取和释放缓冲区，有效减少了 GC 压力，提高了性能。
	for i := range bufsArrs {
		bufsArrs[i] = device.GetMessageBuffer()
		bufs[i] = bufsArrs[i][:]
	}

	defer func() {
		for i := 0; i < maxBatchSize; i++ {
			if bufsArrs[i] != nil {
				device.PutMessageBuffer(bufsArrs[i])
			}
		}
	}()

	// 持续调用 传入的recv函数 接收数据包，并在出现错误时进行相应处理。
	// 使用 deathSpiral 计数器 防止在网络错误时 过度重试。
	for {
		count, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		// handle each packet in the batch
		// 遍历 批量接收的 每个数据包，检查其大小是否足够，然后根据 数据包类型 进行处理。
		for i, size := range sizes[:count] {

			// check size of packet
			// 检查数据包大小是否足够
			if size < MinMessageSize {
				continue
			}

			packet := bufsArrs[i][:size]
			msgType := binary.LittleEndian.Uint32(packet[:4])

			// 数据包类型处理 函数根据数据包类型（通过前 4 字节判断）
			switch msgType {

			// check if transport
			// 传输类型 数据包 (MessageTransportType)：
			case MessageTransportType:
				// 查找对应的密钥对，创建入站元素，并按 对等节点 分类存储。

				// check size
				// 检查数据包大小
				if len(packet) < MessageTransportSize {
					continue
				}

				// lookup key pair
				// 查找对应的密钥对
				receiver := binary.LittleEndian.Uint32(packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter])

				value := device.indexTable.Lookup(receiver)
				keypair := value.keypair
				if keypair == nil {
					continue
				}

				// check keypair expiry
				// 检查密钥对是否过期
				if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
					continue
				}

				// create work element
				// 创建 工作元素 并添加到 对等节点队列
				peer := value.peer
				elem := device.GetInboundElement()
				elem.packet = packet
				elem.buffer = bufsArrs[i]
				elem.keypair = keypair
				elem.endpoint = endpoints[i]
				elem.counter = 0

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsForPeer.Lock()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
				continue

			// otherwise it is a fixed size & handshake related packet
			// 否则，它是一个与握手相关的固定大小的数据包
			case MessageInitiationType:
				// 检查数据包大小
				// 没问题就执行下面的 select 添加到握手队列
				if len(packet) != MessageInitiationSize {
					continue
				}

			case MessageResponseType: // 响应类型 数据包 (MessageResponseType)：
				if len(packet) != MessageResponseSize {
					continue
				}

			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}

			default:
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			// 上面有一个隐式类型过滤：只有以下三种握手相关类型的消息能够通过 switch 语句 并到达 select 部分：

			// MessageInitiationType（握手初始化消息）
			// MessageResponseType（握手响应消息）
			// MessageCookieReplyType（Cookie回复消息）
			// 发送到握手通道，让 握手处理协程 去处理

			// 因此，虽然在 select 语句前没有显式检查 msgType 是否为握手类型，但通过 switch-case 中的 continue 逻辑，实际上已经实现了对消息类型的过滤。
			select {
			case device.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				buffer:   bufsArrs[i],
				packet:   packet,
				endpoint: endpoints[i],
			}:
				// 更新缓冲区
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]

			default:
			}
		}

		// 将处理后的 数据包成员 分发到相应的 对等节点入站队列 和 设备解密队列。
		// 然后 会有对应的携程 消费队列 去处理数据包
		for peer, elemsContainer := range elemsByPeer {
			// 如果 对等节点 正在运行，则将 入站元素容器 添加到 对等节点入站队列 和 设备解密队列。
			// 否则，释放 入站元素容器 中的 所有元素 并删除该容器。
			if peer.isRunning.Load() {
				// RoutineReceiveIncoming → 创建elemsContainer → 发送到两个队列
				//                                     │
				//                                     ├──→ device.queue.decryption.c → RoutineDecryption(修改共享容器) → 设置elem.packet
				//                                     │
				//                                     └──→ peer.queue.inbound.c → RoutineSequentialReceiver(检查elem.packet) → 处理有效数据
				peer.queue.inbound.c <- elemsContainer
				// 下面方法 RoutineDecryption 会从 设备解密队列 中获取加密数据包并解密
				device.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutInboundElement(elem)
				}
				device.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer)
		}
	}
}

// RoutineDecryption 函数是 WireGuard 协议栈中负责解密入站数据包的核心工作协程。
// 这个函数在独立的 goroutine 中运行，专门处理加密传输类型的数据包。
func (device *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: decryption worker %d - stopped", id)
	device.log.Verbosef("Routine: decryption worker %d - started", id)

	// 负责从解密队列 device.queue.decryption.c 中获取加密数据包并解密
	for elemsContainer := range device.queue.decryption.c {
		// 从解密队列接收 QueueInboundElementsContainer 类型的数据包容器
		// 遍历容器中的每个 QueueInboundElement 元素
		for _, elem := range elemsContainer.elems {
			// split message into fields
			// 提取 计数器 和 加密内容
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			// 解析计数器值并准备 nonce
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			// 复制计数器到 nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)

			// 使用 ChaCha20-Poly1305 加密算法 进行解密（通过 elem.keypair.receive.Open 方法）
			// 该算法同时提供加密和认证功能，确保数据的机密性和完整性
			// 将解密后的结果 重新存储到 elem.packet 中
			elem.packet, err = elem.keypair.receive.Open(
				content[:0], // 输出缓冲区（空切片 表示自动分配）
				nonce[:],    // 12字节的 nonce 值
				content,     // 要解密的内容
				nil,         // 附加认证数据（此处为 nil）
			)
			if err != nil {
				elem.packet = nil
			}
		}

		// 处理完容器中的所有元素后，调用 elemsContainer.Unlock() 释放锁
		// 这使得其他协程可以安全地访问和处理这些解密后的数据包
		elemsContainer.Unlock()
	}
}

/*
Handles incoming packets related to handshake
处理与握手相关的传入数据包
*/
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.log.Verbosef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			err := reply.unmarshal(elem.packet)
			if err != nil {
				device.log.Verbosef("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				device.log.Verbosef("Receiving cookie response from %s", elem.endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					device.log.Verbosef("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				device.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode initiation message")
				goto skip
			}

			// consume initiation

			peer := device.ConsumeMessageInitiation(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake initiation", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode response message")
				goto skip
			}

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid response message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake response", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
		}
	skip:
		device.PutMessageBuffer(elem.buffer)
	}
}

// 主要负责 顺序处理 从加密通道接收到的数据包，并将 有效数据包写入到 TUN 设备中。
// 这是 WireGuard 协议栈中 数据接收流程的最后一环，完成 从加密隧道到本地网络栈的数据 交付。
// 该函数在 WireGuard 协议栈的数据接收流程中 处于最后一环：

// 上游：RoutineReceiveIncoming 接收原始数据包 -> RoutineDecryption 解密数据包
// 当前：RoutineSequentialReceiver 验证并处理解密后的数据包
// 下游：写入 TUN 设备，最终交付给本地网络栈

// RoutineSequentialReceiver函数中的"顺序"并不是指恢复原始网络数据包的传输顺序，而是体现在以下几个关键层面：
// 对等节点内部处理顺序：对于单个Peer，所有解密后的数据包都在同一个goroutine中处理，避免了并发访问同一Peer状态时的竞态条件
// 资源锁定顺序：按固定顺序获取和释放锁，防止死锁
// 批量写入顺序：将多个数据包批量写入TUN设备时，保持它们在内存中的组织顺序
// 状态更新顺序：确保与Peer相关的状态（如最近活动时间）按正确的逻辑顺序更新

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)

	// 创建 用于存储 待写入TUN设备的 缓冲区切片
	bufs := make([][]byte, 0, maxBatchSize)

	// 从对等节点的入站队列通道中接收数据包容器
	for elemsContainer := range peer.queue.inbound.c {
		if elemsContainer == nil {
			return
		}

		// 处理容器中的每个数据包：
		// 锁定容器以确保线程安全
		elemsContainer.Lock()
		validTailPacket := -1
		dataPacketReceived := false
		rxBytesLen := uint64(0)

		// 遍历容器中的每个元素，进行一系列验证：
		for i, elem := range elemsContainer.elems {
			// 1. 检查 数据包 是否为空（解密失败）
			// 这意味着 只有当 RoutineDecryption 成功解密 并设置了 elem.packet 字段后，该数据包才会被进一步处理。
			// 延迟处理机制：即使 RoutineSequentialReceiver 先于解密完成获取到了容器，它也会 跳过 未解密的数据包，直到解密完成。
			if elem.packet == nil {
				// decryption failed
				continue
			}
			// 2. 检查 数据包 是否在  replayFilter 中（防止重放攻击）
			if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
				continue
			}
			// 3. 更新 有效数据包索引
			validTailPacket = i
			// 4. 检查 数据包 是否与 密钥对 匹配（确保 握手完成）
			if peer.ReceivedWithKeypair(elem.keypair) {
				peer.SetEndpointFromPacket(elem.endpoint)
				peer.timersHandshakeComplete()
				peer.SendStagedPackets()
			}
			// 5. 更新 接收字节数
			rxBytesLen += uint64(len(elem.packet) + MinMessageSize)

			if len(elem.packet) == 0 {
				device.log.Verbosef("%v - Receiving keepalive packet", peer)
				continue
			}
			dataPacketReceived = true

			// IP数据包验证与过滤：
			switch elem.packet[0] >> 4 {
			case 4: // IPv4数据包处理
				// 验证数据包长度是否合法
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
				length := binary.BigEndian.Uint16(field)
				if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
				// 通过 allowedips 检查 源 IP 地址 是否被允许访问本地网络
				if device.allowedips.Lookup(src) != peer {
					device.log.Verbosef("IPv4 packet with disallowed source address from %v", peer)
					continue
				}

			case 6: // IPv6数据包处理
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
				length := binary.BigEndian.Uint16(field)
				length += ipv6.HeaderLen
				if int(length) > len(elem.packet) {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
				if device.allowedips.Lookup(src) != peer {
					device.log.Verbosef("IPv6 packet with disallowed source address from %v", peer)
					continue
				}

			default:
				device.log.Verbosef("Packet with invalid IP version from %v", peer)
				continue
			}

			bufs = append(bufs, elem.buffer[:MessageTransportOffsetContent+len(elem.packet)])
		}

		// 更新对等节点状态：
		peer.rxBytes.Add(rxBytesLen)
		if validTailPacket >= 0 {
			peer.SetEndpointFromPacket(elemsContainer.elems[validTailPacket].endpoint)
			peer.keepKeyFreshReceiving()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
		}
		// 确保密钥定期更新，保持连接安全
		if dataPacketReceived {
			peer.timersDataReceived()
		}

		// 将有效数据包 批量写入 TUN 设备
		if len(bufs) > 0 {
			_, err := device.tun.device.Write(bufs, MessageTransportOffsetContent)

			if err != nil && !device.isClosed() {
				device.log.Errorf("Failed to write packets to TUN device: %v", err)
			}
		}
		// 将 缓冲区 和 元素容器 归还到对象池，实现资源复用
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutInboundElement(elem)
		}
		bufs = bufs[:0]
		device.PutInboundElementsContainer(elemsContainer)
	}
}
