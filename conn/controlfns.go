/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"syscall"
)

// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it is
// the max supported by a default configuration of macOS. Some platforms will
// silently clamp the value to other maximums, such as linux clamping to
// net.core.{r,w}mem_max (see _linux.go for additional implementation that works
// around this limitation)
const socketBufferSize = 7 << 20

// controlFn is the callback function signature from net.ListenConfig.Control.
// It is used to apply platform specific configuration to the socket prior to
// bind.
type controlFn func(network, address string, c syscall.RawConn) error

// controlFns is a list of functions that are called from the listen config
// that can apply socket options.
var controlFns = []controlFn{}

// listenConfig returns a net.ListenConfig that applies the controlFns to the
// socket prior to bind. This is used to apply socket buffer sizing and packet
// information OOB configuration for sticky sockets.

// 主要作用是创建并返回一个配置了自定义控制函数的 net.ListenConfig 对象。
// 这个配置对象在创建 UDP 套接字时，会应用一系列平台特定的优化和设置，以确保 WireGuard 隧道通信的高效性和稳定性。

// 控制函数链机制
// listenConfig() 函数采用了控制函数链的设计模式，通过全局变量 controlFns 来存储和管理一组套接字配置函数。这种设计有几个显著优势：
// 平台特定实现隔离：不同平台（如 Unix、Linux、Windows）可以通过各自的初始化代码向 controlFns 添加特定的控制函数
func listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			for _, fn := range controlFns {
				if err := fn(network, address, c); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
