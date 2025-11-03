/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

/* Implementation of the TUN device interface for linux
 */

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/rwcancel"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

type NativeTun struct {
	tunFile                 *os.File
	index                   int32      // if index
	errors                  chan error // async error handling
	events                  chan Event // device related events
	netlinkSock             int
	netlinkCancel           *rwcancel.RWCancel
	hackListenerClosed      sync.Mutex
	statusListenersShutdown chan struct{}
	batchSize               int
	vnetHdr                 bool
	udpGSO                  bool

	closeOnce sync.Once

	nameOnce  sync.Once // guards calling initNameCache, which sets following fields
	nameCache string    // name of interface
	nameErr   error

	readOpMu sync.Mutex                    // readOpMu guards readBuff
	readBuff [virtioNetHdrLen + 65535]byte // if vnetHdr every read() is prefixed by virtioNetHdr

	writeOpMu   sync.Mutex // writeOpMu guards toWrite, tcpGROTable
	toWrite     []int
	tcpGROTable *tcpGROTable
	udpGROTable *udpGROTable
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) routineHackListener() {
	defer tun.hackListenerClosed.Unlock()
	/* This is needed for the detection to work across network namespaces
	 * If you are reading this and know a better method, please get in touch.
	 */
	last := 0
	const (
		up   = 1
		down = 2
	)
	for {
		sysconn, err := tun.tunFile.SyscallConn()
		if err != nil {
			return
		}
		err2 := sysconn.Control(func(fd uintptr) {
			_, err = unix.Write(int(fd), nil)
		})
		if err2 != nil {
			return
		}
		switch err {
		case unix.EINVAL:
			if last != up {
				// If the tunnel is up, it reports that write() is
				// allowed but we provided invalid data.
				tun.events <- EventUp
				last = up
			}
		case unix.EIO:
			if last != down {
				// If the tunnel is down, it reports that no I/O
				// is possible, without checking our provided data.
				tun.events <- EventDown
				last = down
			}
		default:
			return
		}
		select {
		case <-time.After(time.Second):
			// nothing
		case <-tun.statusListenersShutdown:
			return
		}
	}
}

func createNetlinkSocket() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR,
	}
	err = unix.Bind(sock, saddr)
	if err != nil {
		return -1, err
	}
	return sock, nil
}

// 主要负责在 Linux 系统上通过 netlink 协议监听 TUN 设备的状态变化。
// 该方法作为一个独立的 goroutine 运行，持续监控网络接口的状态，并在发生变化时通过事件通道通知 WireGuard 主程序。
func (tun *NativeTun) routineNetlinkListener() {
	defer func() {
		unix.Close(tun.netlinkSock)
		tun.hackListenerClosed.Lock()
		close(tun.events)
		tun.netlinkCancel.Close()
	}()

	for msg := make([]byte, 1<<16); ; {
		var err error
		var msgn int
		for {
			msgn, _, _, _, err = unix.Recvmsg(tun.netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			if !tun.netlinkCancel.ReadyRead() {
				tun.errors <- fmt.Errorf("netlink socket closed: %w", err)
				return
			}
		}
		if err != nil {
			tun.errors <- fmt.Errorf("failed to receive netlink message: %w", err)
			return
		}

		select {
		case <-tun.statusListenersShutdown:
			return
		default:
		}

		wasEverUp := false
		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {

			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			if int(hdr.Len) > len(remain) {
				break
			}

			switch hdr.Type {
			case unix.NLMSG_DONE:
				remain = []byte{}

			case unix.RTM_NEWLINK:
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				remain = remain[hdr.Len:]

				if info.Index != tun.index {
					// not our interface
					continue
				}

				if info.Flags&unix.IFF_RUNNING != 0 {
					tun.events <- EventUp
					wasEverUp = true
				}

				if info.Flags&unix.IFF_RUNNING == 0 {
					// Don't emit EventDown before we've ever emitted EventUp.
					// This avoids a startup race with HackListener, which
					// might detect Up before we have finished reporting Down.
					if wasEverUp {
						tun.events <- EventDown
					}
				}

				tun.events <- EventMTUUpdate

			default:
				remain = remain[hdr.Len:]
			}
		}
	}
}

func getIFIndex(name string) (int32, error) {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFINDEX),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return 0, errno
	}

	return *(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])), nil
}

func (tun *NativeTun) setMTU(n int) error {
	name, err := tun.Name()
	if err != nil {
		return err
	}

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// do ioctl call
	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(n)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("failed to set MTU of TUN device: %w", errno)
	}

	return nil
}

func (tun *NativeTun) MTU() (int, error) {
	name, err := tun.Name()
	if err != nil {
		return 0, err
	}

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU of TUN device: %w", errno)
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))), nil
}

func (tun *NativeTun) Name() (string, error) {
	tun.nameOnce.Do(tun.initNameCache)
	return tun.nameCache, tun.nameErr
}

func (tun *NativeTun) initNameCache() {
	tun.nameCache, tun.nameErr = tun.nameSlow()
}

func (tun *NativeTun) nameSlow() (string, error) {
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		return "", err
	}
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	err = sysconn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if err != nil {
		return "", fmt.Errorf("failed to get name of TUN device: %w", err)
	}
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}

func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	tun.writeOpMu.Lock()
	defer func() {
		tun.tcpGROTable.reset()
		tun.udpGROTable.reset()
		tun.writeOpMu.Unlock()
	}()
	var (
		errs  error
		total int
	)
	tun.toWrite = tun.toWrite[:0]
	if tun.vnetHdr {
		err := handleGRO(bufs, offset, tun.tcpGROTable, tun.udpGROTable, tun.udpGSO, &tun.toWrite)
		if err != nil {
			return 0, err
		}
		offset -= virtioNetHdrLen
	} else {
		for i := range bufs {
			tun.toWrite = append(tun.toWrite, i)
		}
	}
	for _, bufsI := range tun.toWrite {
		n, err := tun.tunFile.Write(bufs[bufsI][offset:])
		if errors.Is(err, syscall.EBADFD) {
			return total, os.ErrClosed
		}
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			total += n
		}
	}
	return total, errs
}

// handleVirtioRead splits in into bufs, leaving offset bytes at the front of
// each buffer. It mutates sizes to reflect the size of each element of bufs,
// and returns the number of packets read.
func handleVirtioRead(in []byte, bufs [][]byte, sizes []int, offset int) (int, error) {
	var hdr virtioNetHdr
	err := hdr.decode(in)
	if err != nil {
		return 0, err
	}
	in = in[virtioNetHdrLen:]
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			// This means CHECKSUM_PARTIAL in skb context. We are responsible
			// for computing the checksum starting at hdr.csumStart and placing
			// at hdr.csumOffset.
			err = gsoNoneChecksum(in, hdr.csumStart, hdr.csumOffset)
			if err != nil {
				return 0, err
			}
		}
		if len(in) > len(bufs[0][offset:]) {
			return 0, fmt.Errorf("read len %d overflows bufs element len %d", len(in), len(bufs[0][offset:]))
		}
		n := copy(bufs[0][offset:], in)
		sizes[0] = n
		return 1, nil
	}
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		return 0, fmt.Errorf("unsupported virtio GSO type: %d", hdr.gsoType)
	}

	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	case 6:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	default:
		return 0, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}

	// Don't trust hdr.hdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// csumStart, which is synonymous for IP header length.
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.hdrLen = hdr.csumStart + 8
	} else {
		if len(in) <= int(hdr.csumStart+12) {
			return 0, errors.New("packet is too short")
		}

		tcpHLen := uint16(in[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// A TCP header must be between 20 and 60 bytes in length.
			return 0, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}

	if len(in) < int(hdr.hdrLen) {
		return 0, fmt.Errorf("length of packet (%d) < virtioNetHdr.hdrLen (%d)", len(in), hdr.hdrLen)
	}

	if hdr.hdrLen < hdr.csumStart {
		return 0, fmt.Errorf("virtioNetHdr.hdrLen (%d) < virtioNetHdr.csumStart (%d)", hdr.hdrLen, hdr.csumStart)
	}
	cSumAt := int(hdr.csumStart + hdr.csumOffset)
	if cSumAt+1 >= len(in) {
		return 0, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(in))
	}

	return gsoSplit(in, hdr, bufs, sizes, offset, ipVersion == 6)
}

func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	tun.readOpMu.Lock()
	defer tun.readOpMu.Unlock()
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		readInto := bufs[0][offset:]
		if tun.vnetHdr {
			readInto = tun.readBuff[:]
		}
		n, err := tun.tunFile.Read(readInto)
		if errors.Is(err, syscall.EBADFD) {
			err = os.ErrClosed
		}
		if err != nil {
			return 0, err
		}
		if tun.vnetHdr {
			return handleVirtioRead(readInto[:n], bufs, sizes, offset)
		} else {
			sizes[0] = n
			return 1, nil
		}
	}
}

func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	var err1, err2 error
	tun.closeOnce.Do(func() {
		if tun.statusListenersShutdown != nil {
			close(tun.statusListenersShutdown)
			if tun.netlinkCancel != nil {
				err1 = tun.netlinkCancel.Cancel()
			}
		} else if tun.events != nil {
			close(tun.events)
		}
		err2 = tun.tunFile.Close()
	})
	if err1 != nil {
		return err1
	}
	return err2
}

func (tun *NativeTun) BatchSize() int {
	return tun.batchSize
}

const (
	// TODO: support TSO with ECN bits
	tunTCPOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
	tunUDPOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6
)

func (tun *NativeTun) initFromFlags(name string) error {
	sc, err := tun.tunFile.SyscallConn()
	if err != nil {
		return err
	}
	if e := sc.Control(func(fd uintptr) {
		var (
			ifr *unix.Ifreq
		)
		ifr, err = unix.NewIfreq(name)
		if err != nil {
			return
		}
		err = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr)
		if err != nil {
			return
		}
		got := ifr.Uint16()
		if got&unix.IFF_VNET_HDR != 0 {
			// tunTCPOffloads were added in Linux v2.6. We require their support
			// if IFF_VNET_HDR is set.
			err = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads)
			if err != nil {
				return
			}
			tun.vnetHdr = true
			tun.batchSize = conn.IdealBatchSize
			// tunUDPOffloads were added in Linux v6.2. We do not return an
			// error if they are unsupported at runtime.
			tun.udpGSO = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads|tunUDPOffloads) == nil
		} else {
			tun.batchSize = 1
		}
	}); e != nil {
		return e
	}
	return err
}

// CreateTUN creates a Device with the provided name and MTU.
// CreateTUN 在 Linux 系统上创建一个指定名称和 MTU 的 TUN 虚拟网络设备
// 参数:
//
//	name - TUN 设备的名称
//	mtu - 设备的最大传输单元大小
//
// 返回值:
//
//	Device - 实现了 Device 接口的 TUN 设备实例
//	error - 操作过程中遇到的任何错误
func CreateTUN(name string, mtu int) (Device, error) {
	// 打开 TUN 设备克隆文件 /dev/net/tun
	// O_RDWR: 以读写模式打开设备
	// O_CLOEXEC: 设置文件描述符在执行新程序时自动关闭
	nfd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CreateTUN(%q) failed; %s does not exist", name, cloneDevicePath)
		}
		return nil, err
	}

	// 创建 ifreq 结构体并设置设备名称
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	// IFF_VNET_HDR enables the "tun status hack" via routineHackListener()
	// where a null write will return EINVAL indicating the TUN is up.

	// 设置 TUN 设备标志：
	// IFF_TUN: 创建三层 IP 设备 而非二层以太网设备
	// IFF_NO_PI: 不包含数据包信息（避免额外包头）
	// IFF_VNET_HDR: 启用 virtio 网络头部，支持性能优化和接口状态检测
	// IFF_VNET_HDR 启用 "tun status hack" 功能，通过 routineHackListener()
	// 检测接口状态 - 当向设备写入空数据 返回 EINVAL 时表示 TUN 接口已启用
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)

	// 通过 TUNSETIFF IOCTL 命令 将设置 应用到设备
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		return nil, err
	}

	// 将 文件描述符 设置为非阻塞模式，防止在没有数据时阻塞 goroutine
	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.

	// 注意：以上步骤（打开、IOCTL配置、设置非阻塞）必须在
	// 将 文件描述符 传递给 netpoll 相关操作之前完成

	// 将 Unix 文件描述符转换为 Go 语言的 os.File 对象

	fd := os.NewFile(uintptr(nfd), cloneDevicePath)

	// 调用 CreateTUNFromFile 完成后续初始化 并返回设备实例
	return CreateTUNFromFile(fd, mtu)
}

// CreateTUNFromFile creates a Device from an os.File with the provided MTU.
// 负责 从已有的文件对象 创建和初始化 TUN 虚拟网络设备。
// 该 函数 接收一个已打开的 os.File 对象 和指定的 MTU 值，返回一个实现了 Device 接口的 NativeTun 设备实例。
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	// 创建 NativeTun 结构体实例 并初始化各项字段：
	tun := &NativeTun{
		tunFile:                 file,                                //保存传入的文件对象
		events:                  make(chan Event, 5),                 // 创建用于传递设备事件的带缓冲通道（
		errors:                  make(chan error, 5),                 // 创建用于传递错误信息的带缓冲通道
		statusListenersShutdown: make(chan struct{}),                 // 创建用于通知监听器关闭的通道
		tcpGROTable:             newTCPGROTable(),                    // 初始化 TCP 分段重组表
		udpGROTable:             newUDPGROTable(),                    // 初始化 UDP 分段重组表
		toWrite:                 make([]int, 0, conn.IdealBatchSize), // 初始化用于批处理写操作的索引切片
	}

	// 获取设备名称并初始化设备标志
	name, err := tun.Name()
	if err != nil {
		return nil, err
	}
	// 调用 tun.initFromFlags() 根据设备标志初始化设备特性（如是否支持VIRTIO头部、批处理大小等）
	err = tun.initFromFlags(name)
	if err != nil {
		return nil, err
	}

	// start event listener
	// 获取 网络接口索引（通过 SIOCGIFINDEX ioctl）
	tun.index, err = getIFIndex(name)
	if err != nil {
		return nil, err
	}

	// 创建 netlink 套接字 用于监听网络接口状态变化
	tun.netlinkSock, err = createNetlinkSocket()
	if err != nil {
		return nil, err
	}
	// 为 netlink 套接字创建取消读取功能，用于在需要时及时关闭监听
	tun.netlinkCancel, err = rwcancel.NewRWCancel(tun.netlinkSock)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}

	tun.hackListenerClosed.Lock()

	// routineNetlinkListener(): 通过 netlink 协议 监听接口状态变化（如接口上线/下线、MTU变更等）
	// 这里面检测到接口 状态变化 后 会 触发 events 通道 发送 对应事件，这样消费端就可以启动 UDP 监听了
	go tun.routineNetlinkListener()

	// routineHackListener(): 提供一种跨网络命名空间检测接口状态的替代方法（通过向设备写入空数据并检测错误类型）
	go tun.routineHackListener() // cross namespace

	err = tun.setMTU(mtu)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}

	return tun, nil
}

// CreateUnmonitoredTUNFromFD creates a Device from the provided file
// descriptor.
func CreateUnmonitoredTUNFromFD(fd int) (Device, string, error) {
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "/dev/tun")
	tun := &NativeTun{
		tunFile:     file,
		events:      make(chan Event, 5),
		errors:      make(chan error, 5),
		tcpGROTable: newTCPGROTable(),
		udpGROTable: newUDPGROTable(),
		toWrite:     make([]int, 0, conn.IdealBatchSize),
	}
	name, err := tun.Name()
	if err != nil {
		return nil, "", err
	}
	err = tun.initFromFlags(name)
	if err != nil {
		return nil, "", err
	}
	return tun, name, err
}
