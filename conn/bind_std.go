/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	// 强制编译器检查 *StdNetBind 是否真的实现了 Bind 接口：
	_ Bind = (*StdNetBind)(nil)
)

// StdNetBind implements Bind for all platforms. While Windows has its own Bind
// (see bind_windows.go), it may fall back to StdNetBind.
// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type StdNetBind struct {
	mu            sync.Mutex // protects all fields except as specified
	ipv4          *net.UDPConn
	ipv6          *net.UDPConn
	ipv4PC        *ipv4.PacketConn // will be nil on non-Linux
	ipv6PC        *ipv6.PacketConn // will be nil on non-Linux
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool

	blackhole4 bool
	blackhole6 bool
}

func NewStdNetBind() Bind {
	return &StdNetBind{
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		msgsPool: sync.Pool{
			New: func() any {
				// ipv6.Message and ipv4.Message are interchangeable as they are
				// both aliases for x/net/internal/socket.Message.
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},
	}
}

type StdNetEndpoint struct {
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current sticky source address and interface index, if
	// supported. Typically this is a PKTINFO structure from/for control
	// messages, see unix.PKTINFO for an example.
	src []byte
}

var (
	_ Bind     = (*StdNetBind)(nil)
	_ Endpoint = &StdNetEndpoint{}
)

func (*StdNetBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (e *StdNetEndpoint) ClearSrc() {
	if e.src != nil {
		// Truncate src, no need to reallocate.
		e.src = e.src[:0]
	}
}

func (e *StdNetEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

// See control_default,linux, etc for implementations of SrcIP and SrcIfidx.

func (e *StdNetEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *StdNetEndpoint) DstToString() string {
	return e.AddrPort.String()
}

// 用于创建特定网络类型的 UDP 监听连接。这里指的是 udp4 或 udp6。
// 该函数封装了 底层网络监听 创建逻辑，并处理了端口绑定和地址解析等细节
func listenNet(network string, port int) (*net.UDPConn, int, error) {
	// 调用 listenConfig() 获取一个配置了平台特定优化的 net.ListenConfig 对象
	conn, err := listenConfig().
		// 使用这个配置对象的 ListenPacket 方法 创建一个 UDP 监听(其实是只绑定了端口，并没有向 TCP 那样持续监听某个端口)
		ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	// 当 指定端口为 0 时，系统会自动分配一个可用端口。
	// 这段代码 通过解析实际绑定的 本地地址，获取 系统分配的 端口号。
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	// 将通用的 net.PacketConn 接口 转换为具体的 *net.UDPConn 类型，并返回连接对象、实际端口号和错误状态。
	return conn.(*net.UDPConn), uaddr.Port, nil
}

// 返回值：
// - fns：一个包含两个 ReceiveFunc 函数的切片，分别用于接收 IPv4 和 IPv6 数据包。
// - port：实际绑定的端口号。
// - err：如果发生错误，返回错误信息；否则为 nil。
func (s *StdNetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	// 通过 互斥锁 确保网络绑定操作的线程安全，防止并发访问导致的数据竞争。
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	// 检查绑定是否已经打开，如果是则返回错误，避免重复打开。
	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
	// IPv4 和 IPv6 监听端点创建
	// 尝试在指定端口（或自动选择端口）上同时创建 IPv4 和 IPv6 的 UDP 监听端点。
	// 函数使用 listenNet 辅助函数来实际创建网络连接。
again:
	port := int(uport)
	var v4conn, v6conn *net.UDPConn
	var v4pc *ipv4.PacketConn
	var v6pc *ipv6.PacketConn

	// 创建 IPv4 监听端点
	// 尝试在指定端口（或自动选择端口）上创建 IPv4 的 UDP 监听端点。
	// 如果失败（如地址不支持 IPv4），会记录错误信息并继续尝试。
	v4conn, port, err = listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	v6conn, port, err = listenNet("udp6", port)
	// 当指定端口为 0（自动选择端口）且遇到地址已使用错误时，实现了一个最大重试 100 次的机制，以尝试找到一个可用端口。
	// 这是一种提高端口分配成功率的容错设计。
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		v4conn.Close()
		return nil, 0, err
	}

	var fns []ReceiveFunc
	// 检测当 前网络连接 是否支持 UDP 卸载功能（如校验和计算卸载），这是一种性能优化措施，可以将一些网络处理任务 从 CPU 卸载到 网络硬件。
	if v4conn != nil {
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v4pc = ipv4.NewPacketConn(v4conn)
			s.ipv4PC = v4pc
		}
		// 创建 IPv4 接收函数
		// 为 IPv4 连接 创建一个 接收函数，用于处理传入的 IPv4 数据包。
		// 这个函数 会被添加到 返回的 接收函数列表中，稍后会被用于 数据接收。
		fns = append(fns, s.makeReceiveIPv4(v4pc, v4conn, s.ipv4RxOffload))
		// 记录监听 IPv4 连接，这个链接 后续会被用于发送数据。
		s.ipv4 = v4conn
	}
	if v6conn != nil {
		s.ipv6TxOffload, s.ipv6RxOffload = supportsUDPOffload(v6conn)
		// 在 Linux 和 Android 平台上，创建特定的数据包连接对象，可能用于后续的高级网络操作或性能优化。
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v6pc = ipv6.NewPacketConn(v6conn)
			s.ipv6PC = v6pc
		}

		// 为 每个成功创建的网络连接 生成对应的 接收函数，并将这些 函数 添加到返回列表中。
		// 这些 接收函数 稍后会被传递给 RoutineReceiveIncoming 协程 用于实际的数据接收。
		fns = append(fns, s.makeReceiveIPv6(v6pc, v6conn, s.ipv6RxOffload))
		s.ipv6 = v6conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	// 返回 IPv4 和 IPv6 接收函数列表、实际绑定的端口号和 nil 错误。
	return fns, uint16(port), nil
}

func (s *StdNetBind) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *StdNetBind) getMessages() *[]ipv6.Message {
	return s.msgsPool.Get().(*[]ipv6.Message)
}

var (
	// If compilation fails here these are no longer the same underlying type.
	_ ipv6.Message = ipv4.Message{}
)

type batchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

func (s *StdNetBind) receiveIP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	bufs [][]byte,
	sizes []int,
	eps []Endpoint,
) (n int, err error) {
	msgs := s.getMessages()
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	defer s.putMessages(msgs)
	var numMsgs int
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if rxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			numMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, err
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, err
			}
		} else {
			numMsgs, err = br.ReadBatch(*msgs, 0)
			if err != nil {
				return 0, err
			}
		}
	} else {
		msg := &(*msgs)[0]
		msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1
	}
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		if sizes[i] == 0 {
			continue
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := &StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		eps[i] = ep
	}
	return numMsgs, nil
}

func (s *StdNetBind) makeReceiveIPv4(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
	}
}

func (s *StdNetBind) makeReceiveIPv6(pc *ipv6.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
	}
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return IdealBatchSize
	}
	return 1
}

func (s *StdNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err1, err2 error
	if s.ipv4 != nil {
		err1 = s.ipv4.Close()
		s.ipv4 = nil
		s.ipv4PC = nil
	}
	if s.ipv6 != nil {
		err2 = s.ipv6.Close()
		s.ipv6 = nil
		s.ipv6PC = nil
	}
	s.blackhole4 = false
	s.blackhole6 = false
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false
	if err1 != nil {
		return err1
	}
	return err2
}

type ErrUDPGSODisabled struct {
	onLaddr  string
	RetryErr error
}

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf("disabled UDP GSO on %s, NIC(s) may not support checksum offload", e.onLaddr)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}

// 调用链条 RoutineSequentialSender  goroutine -> peer.SendBuffers->peer.device.net.bind.Send(buffers, endpoint)
// 它负责将批量加密数据包 通过 UDP 协议 发送到指定的 网络端点。

// bufs [][]byte：二维字节切片，表示要发送的多个数据包
// endpoint Endpoint：目标网络端点，包含了目标 IP 地址和端口信息
func (s *StdNetBind) Send(bufs [][]byte, endpoint Endpoint) error {
	s.mu.Lock()
	// 拿到 对应协议的 监听连接，使用这个连接 发送数据
	conn := s.ipv4

	// 获取相关配置：黑洞模式标志、UDP GSO（通用分段卸载）支持标志、批处理写入器等
	blackhole := s.blackhole4
	offload := s.ipv4TxOffload
	br := batchWriter(s.ipv4PC)

	is6 := false
	if endpoint.DstIP().Is6() {
		blackhole = s.blackhole6
		conn = s.ipv6
		br = s.ipv6PC
		is6 = true
		offload = s.ipv6TxOffload
	}
	s.mu.Unlock()

	// 如果启用了黑洞模式（丢弃所有出站数据包），则直接返回成功
	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}

	// 从 对象池中 获取 消息数组 和 UDP地址对象（资源复用优化）
	msgs := s.getMessages()
	defer s.putMessages(msgs)

	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)

	// 根据 IP类型 复制 目标地址信息 到 UDP地址对象
	if is6 {
		as16 := endpoint.DstIP().As16()
		copy(ua.IP, as16[:])
		ua.IP = ua.IP[:16]
	} else {
		as4 := endpoint.DstIP().As4()
		copy(ua.IP, as4[:])
		ua.IP = ua.IP[:4]
	}
	// 设置目标端口号
	ua.Port = int(endpoint.(*StdNetEndpoint).Port())
	var (
		retried bool
		err     error
	)

retry:

	// 函数根据是否启用 UDP GSO 功能，采用两种不同的发送策略：
	// 如果启用了 UDP GSO 功能，使用 coalesceMessages 函数 将多个数据包 合并为一个 UDP 分段，
	// 并设置 GSO 大小。
	if offload {
		// 数据包合并：通过 coalesceMessages 函数将多个小型 UDP 数据包 合并成一个大型 GSO 数据包
		// GSO 大小设置：使用 setGSOSize 函数设置每个子分段的大小，通常等于 MTU 减去头部开销
		n := coalesceMessages(ua, endpoint.(*StdNetEndpoint), bufs, *msgs, setGSOSize)
		// Bind 接口设计：在 conn.go 中定义的 Bind 接口，其 Open 方法负责在给定端口上创建监听状态，而Send方法则使用 同一个绑定的连接 发送数据。
		err = s.send(conn, br, (*msgs)[:n])
		if err != nil && offload && errShouldDisableUDPGSO(err) {
			offload = false
			s.mu.Lock()
			if is6 {
				s.ipv6TxOffload = false
			} else {
				s.ipv4TxOffload = false
			}
			s.mu.Unlock()

			// 如果遇到 GSO 相关错误，会禁用 GSO 并尝试重试
			retried = true
			goto retry
		}
	} else { // 未启用UDP GSO时的发送
		// 逐个处理数据包，为 msg 设置目标地址和数据缓冲区
		for i := range bufs {
			(*msgs)[i].Addr = ua
			(*msgs)[i].Buffers[0] = bufs[i]
			// 设置 mas 消息的 源地址控制信息
			setSrcControl(&(*msgs)[i].OOB, endpoint.(*StdNetEndpoint))
		}
		// 调用内部的 send 方法 批量发送所有数据包
		err = s.send(conn, br, (*msgs)[:len(bufs)])
	}

	// 如果发生了GSO重试，返回特定的GSO禁用错误
	if retried {
		return ErrUDPGSODisabled{onLaddr: conn.LocalAddr().String(), RetryErr: err}
	}

	return err
}

// 虽然函数签名中使用了 ipv6.Message 类型，但实际上它被设计为一个通用发送函数，同时支持 IPv4 和 IPv6 数据包
// 它位于 整个发送流程的 末端，负责将上层准备好的数据 转换为实际的网络传输操作
// 共享数据结构：虽然 send 函数参数是 ipv6.Message 类型，但在 Go 的网络实现中，IPv4 和 IPv6 消息共享相似的数据结构，可以通过统一接口处理
// 运行时适配：在 send 函数内部，通过 msg.Addr.(*net.UDPAddr) 类型断言，统一获取目标地址，而不关心其具体是 IPv4 还是 IPv6
func (s *StdNetBind) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	// GSO 合并模式：当启用 GSO 时，通过 coalesceMessages 将多个小包合并为一个大的 GSO 包，然后调用 send 函数一次性发送
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
		return err
	}

	// 普通发送模式：未启用 GSO 时，逐个设置每个数据包的地址和缓冲区信息，然后通过 send 函数批量发送
	for _, msg := range msgs {
		// msg.Addr.(*net.UDPAddr) 这里断言UDP 地址，而不关心具体是 IPv4 还是 IPv6
		_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
		if err != nil {
			break
		}
	}
	return err
}

const (
	// Exceeding these values results in EMSGSIZE. They account for layer3 and
	// layer4 headers. IPv6 does not need to account for itself as the payload
	// length field is self excluding.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen = 1<<16 - 1 - 8

	// This is a hard limit imposed by the kernel.
	udpSegmentMaxDatagrams = 64
)

type setGSOFunc func(control *[]byte, gsoSize uint16)

func coalesceMessages(addr *net.UDPAddr, ep *StdNetEndpoint, bufs [][]byte, msgs []ipv6.Message, setGSO setGSOFunc) int {
	var (
		base     = -1 // index of msg we are currently coalescing into
		gsoSize  int  // segmentation size of msgs[base]
		dgramCnt int  // number of dgrams coalesced into msgs[base]
		endBatch bool // tracking flag to start a new batch on next iteration of bufs
	)
	maxPayloadLen := maxIPv4PayloadLen
	if ep.DstIP().Is6() {
		maxPayloadLen = maxIPv6PayloadLen
	}
	for i, buf := range bufs {
		if i > 0 {
			msgLen := len(buf)
			baseLenBefore := len(msgs[base].Buffers[0])
			freeBaseCap := cap(msgs[base].Buffers[0]) - baseLenBefore
			if msgLen+baseLenBefore <= maxPayloadLen &&
				msgLen <= gsoSize &&
				msgLen <= freeBaseCap &&
				dgramCnt < udpSegmentMaxDatagrams &&
				!endBatch {
				msgs[base].Buffers[0] = append(msgs[base].Buffers[0], buf...)
				if i == len(bufs)-1 {
					setGSO(&msgs[base].OOB, uint16(gsoSize))
				}
				dgramCnt++
				if msgLen < gsoSize {
					// A smaller than gsoSize packet on the tail is legal, but
					// it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			setGSO(&msgs[base].OOB, uint16(gsoSize))
		}
		// Reset prior to incrementing base since we are preparing to start a
		// new potential batch.
		endBatch = false
		base++
		gsoSize = len(buf)
		setSrcControl(&msgs[base].OOB, ep)
		msgs[base].Buffers[0] = buf
		msgs[base].Addr = addr
		dgramCnt = 1
	}
	return base + 1
}

type getGSOFunc func(control []byte) (int, error)

func splitCoalescedMessages(msgs []ipv6.Message, firstMsgAt int, getGSO getGSOFunc) (n int, err error) {
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, err
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		gsoSize, err = getGSO(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			// It is legal for bytes to move within msg.Buffers[0] as a result
			// of splitting, so we only zero the source msg len when it is not
			// the destination of the last split operation above.
			msg.N = 0
		}
	}
	return n, nil
}
