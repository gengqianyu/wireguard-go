/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package conn implements WireGuard's network connections.
package conn

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
)

const (
	IdealBatchSize = 128 // maximum number of packets handled per read and write
)

// A ReceiveFunc receives at least one packet from the network and writes them
// into packets. On a successful read it returns the number of elements of
// sizes, packets, and endpoints that should be evaluated. Some elements of
// sizes may be zero, and callers should ignore them. Callers must pass a sizes
// and eps slice with a length greater than or equal to the length of packets.
// These lengths must not exceed the length of the associated Bind.BatchSize().
// ReceiveFunc 从网络接收至少一个数据包并将其写入 packets 中。
// 成功读取时，它返回应该评估的 sizes、packets 和 endpoints 元素的数量。
// sizes 的某些元素 可能为零，调用者应该忽略它们。
// 调用者 必须传递长度大于或等于 packets 长度的 sizes 和 eps 切片。
// 这些长度不能超过关联的 Bind.BatchSize() 的长度。
type ReceiveFunc func(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error)

// A Bind listens on a port for both IPv6 and IPv4 UDP traffic.
//
// A Bind interface may also be a PeekLookAtSocketFd or BindSocketToInterface,
// depending on the platform-specific implementation.

//  Bind 接口的核心功能：同时处理 IPv6 和 IPv4 的 UDP 网络流量
//  Bind 接口的扩展性：根据不同平台的实现，它还可能实现其他接口（PeekLookAtSocketFd 或 BindSocketToInterface）

// Bind 接口：纯粹的软件抽象，定义在 wireguard-go 的代码层，负责管理 UDP 套接字、处理数据包的发送和接收，是 WireGuard 协议实现的网络通信基础。
type Bind interface {
	// Open puts the Bind into a listening state on a given port and reports the actual
	// port that it bound to. Passing zero results in a random selection.
	// fns is the set of functions that will be called to receive packets.
	// 它负责将 Bind 实例置于监听状态，使其能够接收来自网络的 UDP 数据包。
	// Open 将 Bind 置于给定端口上的监听状态，并报告实际绑定的端口。
	// 传递 0 端口会随机选择可用端口。
	// fns 是用于接收数据包的函数集合。
	Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error)

	// Close closes the Bind listener.
	// All fns returned by Open must return net.ErrClosed after a call to Close.
	// Close 关闭 Bind 监听器。
	// 调用 Close 后，所有通过 Open 返回的 ReceiveFunc 必须返回 net.ErrClosed。
	Close() error

	// SetMark sets the mark for each packet sent through this Bind.
	// This mark is passed to the kernel as the socket option SO_MARK.
	// SetMark 设置通过此 Bind 发送的每个数据包的标记。
	// 该标记会被传递给 内核 作为套接字选项 SO_MARK。
	SetMark(mark uint32) error

	// Send writes one or more packets in bufs to address ep. The length of
	// bufs must not exceed BatchSize().
	// Send 将一个或多个数据包 bufs 发送到地址 ep。bufs 的长度不能超过 BatchSize()。
	Send(bufs [][]byte, ep Endpoint) error

	// ParseEndpoint creates a new endpoint from a string.
	// ParseEndpoint 创建一个新的 Endpoint 实例，从字符串 s 中解析出 IP 地址和端口号。
	ParseEndpoint(s string) (Endpoint, error)

	// BatchSize is the number of buffers expected to be passed to the ReceiveFuncs,
	// and the maximum expected to be passed to SendBatch.
	// BatchSize 返回每个 ReceiveFunc 期望接收的数据包缓冲区数量，
	// 以及 SendBatch 方法期望发送的最大数据包数量。
	BatchSize() int
}

// BindSocketToInterface is implemented by Bind objects that support being
// tied to a single network interface. Used by wireguard-windows.
// BindSocketToInterface 由支持绑定到单个网络接口的 Bind 对象实现。
// 被 wireguard-windows 使用。
type BindSocketToInterface interface {
	BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error
	BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error
}

// PeekLookAtSocketFd is implemented by Bind objects that support having their
// file descriptor peeked at. Used by wireguard-android.
// PeekLookAtSocketFd 由支持查看其文件描述符的 Bind 对象实现。
// 被 wireguard-android 使用。
type PeekLookAtSocketFd interface {
	PeekLookAtSocketFd4() (fd int, err error)
	PeekLookAtSocketFd6() (fd int, err error)
}

// An Endpoint maintains the source/destination caching for a peer.
//
//	dst: the remote address of a peer ("endpoint" in uapi terminology)
//	src: the local address from which datagrams originate going to the peer
//
// Endpoint 维护对对等方 的源/目的地址缓存。
// dst：对端地址（在 uapi 术语中称为“endpoint”）
// src：从本地地址发送到对端的数据包的源地址
type Endpoint interface {
	ClearSrc()           // clears the source address 清除源地址
	SrcToString() string // returns the local source address (ip:port) 返回本地源地址（ip:port）
	DstToString() string // returns the destination address (ip:port) 返回对端地址（ip:port）
	DstToBytes() []byte  // used for mac2 cookie calculations 返回对端地址的字节表示（用于 mac2  cookie 计算）
	DstIP() netip.Addr   // returns the destination IP address 返回对端 IP 地址
	SrcIP() netip.Addr   // returns the source IP address 返回本地源 IP 地址
}

var (
	ErrBindAlreadyOpen   = errors.New("bind is already open")
	ErrWrongEndpointType = errors.New("endpoint type does not correspond with bind type")
)

func (fn ReceiveFunc) PrettyName() string {
	name := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
	// 0. cheese/taco.beansIPv6.func12.func21218-fm
	name = strings.TrimSuffix(name, "-fm")
	// 1. cheese/taco.beansIPv6.func12.func21218
	if idx := strings.LastIndexByte(name, '/'); idx != -1 {
		name = name[idx+1:]
		// 2. taco.beansIPv6.func12.func21218
	}
	for {
		var idx int
		for idx = len(name) - 1; idx >= 0; idx-- {
			if name[idx] < '0' || name[idx] > '9' {
				break
			}
		}
		if idx == len(name)-1 {
			break
		}
		const dotFunc = ".func"
		if !strings.HasSuffix(name[:idx+1], dotFunc) {
			break
		}
		name = name[:idx+1-len(dotFunc)]
		// 3. taco.beansIPv6.func12
		// 4. taco.beansIPv6
	}
	if idx := strings.LastIndexByte(name, '.'); idx != -1 {
		name = name[idx+1:]
		// 5. beansIPv6
	}
	if name == "" {
		return fmt.Sprintf("%p", fn)
	}
	if strings.HasSuffix(name, "IPv4") {
		return "v4"
	}
	if strings.HasSuffix(name, "IPv6") {
		return "v6"
	}
	return name
}
