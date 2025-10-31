//go:build darwin || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type UAPIListener struct {
	listener net.Listener // unix socket listener
	connNew  chan net.Conn
	connErr  chan error
	kqueueFd int
	keventFd int
}

func (l *UAPIListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-l.connNew:
			return conn, nil

		case err := <-l.connErr:
			return nil, err
		}
	}
}

func (l *UAPIListener) Close() error {
	err1 := unix.Close(l.kqueueFd)
	err2 := unix.Close(l.keventFd)
	err3 := l.listener.Close()
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

// UAPIListen 在 BSD 系统上创建一个用户空间 API 监听器
// 参数:
//
//	name: WireGuard 设备名称
//	file: 用于监听的文件描述符对应的文件对象
//
// 返回值:
//
//	net.Listener: 可用于接受 UAPI 连接的监听器
//	error: 操作过程中可能发生的错误
func UAPIListen(name string, file *os.File) (net.Listener, error) {
	// wrap file in listener
	// 将文件对象 包装 为网络监听器
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}

	// 创建 UAPIListener 结构体实例，封装底层 监听器和通信通道
	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1), // 用于传递新建立的连接
		connErr:  make(chan error, 1),    // 用于传递错误信息
	}

	// 如果监听器 是 Unix 监听器类型，设置关闭时 自动删除套接字文件
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}

	// 获取套接字文件路径
	socketPath := sockPath(name)

	// watch for deletion of socket
	// 创建 kqueue 实例 用于监控套接字文件的删除事件
	// 2. 什么是 kqueue？作用是什么？
	// kqueue 是 BSD 系列操作系统（如 FreeBSD、macOS、iOS 等）提供的一种高效 I/O 事件通知机制，类似于 Linux 中的 epoll 或 Windows 中的 IOCP。
	// 它的核心作用是：让程序可以同时监控多个文件描述符（如网络套接字、本地文件、管道等）上的事件，并在事件发生时得到通知。
	uapi.kqueueFd, err = unix.Kqueue()
	if err != nil {
		return nil, err
	}

	// 打开套接字目录用于监控 "/var/run/wireguard" 目录的变化
	uapi.keventFd, err = unix.Open(socketDirectory, unix.O_RDONLY, 0)
	if err != nil {
		unix.Close(uapi.kqueueFd)
		return nil, err
	}

	// 启动一个 goroutine 监控套接字文件 的删除事件
	go func(l *UAPIListener) {
		// 设置 kqueue 事件，监控目录的 VNODE（虚拟节点）事件
		event := unix.Kevent_t{
			Filter: unix.EVFILT_VNODE,                              // 监控 VNODE 事件
			Flags:  unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT, // 添加、启用事件并设为一次性
			Fflags: unix.NOTE_WRITE,                                // 监控写事件（用于检测删除）
		}
		// Allow this assignment to work with both the 32-bit and 64-bit version
		// of the above struct. If you know another way, please submit a patch.
		// 兼容 32 位和 64 位系统的事件标识符设置
		*(*uintptr)(unsafe.Pointer(&event.Ident)) = uintptr(uapi.keventFd)
		events := make([]unix.Kevent_t, 1)
		n := 1
		var kerr error

		// 监控循环
		for {
			// start with lstat to avoid race condition
			// 先检查套接字文件 是否存在，避免竞态条件
			if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
				l.connErr <- err
				return
			}
			// 检查 kqueue 操作是否出错
			if (kerr != nil || n != 1) && kerr != unix.EINTR {
				if kerr != nil {
					l.connErr <- kerr
				} else {
					l.connErr <- errors.New("kqueue returned empty")
				}
				return
			}
			// 等待 kqueue 事件通知
			n, kerr = unix.Kevent(uapi.kqueueFd, []unix.Kevent_t{event}, events, nil)
		}
	}(uapi)

	// watch for new connections
	// 启动另一个 goroutine 用于接受新的连接
	go func(l *UAPIListener) {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				l.connErr <- err
				break
			}
			l.connNew <- conn // 将新连接发送到通道
		}
	}(uapi)

	return uapi, nil
}
