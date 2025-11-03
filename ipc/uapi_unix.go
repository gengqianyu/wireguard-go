//go:build linux || darwin || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	IpcErrorIO        = -int64(unix.EIO)
	IpcErrorProtocol  = -int64(unix.EPROTO)
	IpcErrorInvalid   = -int64(unix.EINVAL)
	IpcErrorPortInUse = -int64(unix.EADDRINUSE)
	IpcErrorUnknown   = -55 // ENOANO
)

// socketDirectory is variable because it is modified by a linker
// flag in wireguard-android.
var socketDirectory = "/var/run/wireguard"

func sockPath(iface string) string {
	return fmt.Sprintf("%s/%s.sock", socketDirectory, iface)
}

// 该函数负责创建和初始化 UNIX 域套接字文件，作为 WireGuard 用户空间 API (UAPI) 的通信端点，使外部程序（如 wg 命令行工具）能够与 wireguard-go 进程进行交互。
// - **参数**：`name string` - WireGuard 网络接口的名称（如 "wg0"、"wg1" 等）
// - **返回值**：
//   - `*os.File` - 配置好的 UNIX 套接字文件对象，可用于后续创建监听器
//   - `error` - 如果出现任何错误，返回具体错误信息
func UAPIOpen(name string) (*os.File, error) {
	// 1. **创建套接字目录**
	if err := os.MkdirAll(socketDirectory, 0o755); err != nil {
		return nil, err
	}
	// 确保存放套接字文件的目录存在，如果不存在则创建，目录权限设置为 0o755（所有者可读写执行，组和其他用户可读执行）。

	// 2. **生成套接字路径**
	// 调用 `sockPath` 辅助函数，生成形如 `/var/run/wireguard/接口名.sock` 的完整路径。
	socketPath := sockPath(name)

	// 3. **解析 UNIX 地址**
	//  将文件路径解析为 Go 标准库可识别的 UNIX 套接字地址对象。
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}

	// 4. **设置文件掩码**
	// 设置文件创建掩码为 0o077（确保新创建的文件只有所有者有读写权限），并使用 defer 确保函数返回前恢复原始掩码。
	oldUmask := unix.Umask(0o077)
	defer unix.Umask(oldUmask)

	// 5. **创建监听器**
	// 尝试创建 UNIX 套接字 监听器，如果成功则直接返回监听器的文件对象。
	listener, err := net.ListenUnix("unix", addr)
	if err == nil {
		return listener.File()
	}

	// 6. **错误处理与恢复**
	//    如果首次创建失败，函数会执行以下恢复步骤：
	// Test socket, if not in use cleanup and try again.
	// 检查套接字是否被其他进程占用
	if _, err := net.Dial("unix", socketPath); err == nil {
		return nil, errors.New("unix socket in use")
	}
	// 如果套接字未被占用但文件存在，尝试删除
	if err := os.Remove(socketPath); err != nil {
		return nil, err
	}
	// 再次尝试创建监听器
	listener, err = net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	return listener.File()
}
