/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/rwcancel"
)

type UAPIListener struct {
	listener        net.Listener // unix socket listener
	connNew         chan net.Conn
	connErr         chan error
	inotifyFd       int
	inotifyRWCancel *rwcancel.RWCancel
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
	err1 := unix.Close(l.inotifyFd)
	err2 := l.inotifyRWCancel.Cancel()
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

// UAPIListen 函数是 wireguard-go 项目在 Linux 平台上实现的用户空间 API(UAPI) 监听器创建函数，用于监听来自配置工具的连接请求并进行处理。
func UAPIListen(name string, file *os.File) (net.Listener, error) {
	// wrap file in listener
	// 将文件描述符 包装为 net.Listener 类型
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}

	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}
	// 这部分代码将传入的文件对象转换为标准的Go网络监听器。
	// 特别地，当识别出这是一个Unix监听器时，设置SetUnlinkOnClose(true)选项，确保监听器关闭时自动删除对应的套接字文件，防止文件残留。

	// 创建一个自定义的 UAPIListener 结构体实例，包含原始监听器和两个通道：一个用于传递新的连接，一个用于传递错误信息。
	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	// watch for deletion of socket

	socketPath := sockPath(name)

	// 使用Linux的inotify机制监控套接字文件的变化。
	uapi.inotifyFd, err = unix.InotifyInit()
	if err != nil {
		return nil, err
	}

	_, err = unix.InotifyAddWatch(
		uapi.inotifyFd,
		socketPath,
		unix.IN_ATTRIB| // 文件属性变化
			unix.IN_DELETE| // 文件被删除
			unix.IN_DELETE_SELF, // 监控对象自身被删除
	)

	if err != nil {
		return nil, err
	}

	// 创建一个可取消的 读写 操作封装，允许在需要时 中断 对inotify文件描述符 的读取操作。
	uapi.inotifyRWCancel, err = rwcancel.NewRWCancel(uapi.inotifyFd)
	if err != nil {
		unix.Close(uapi.inotifyFd)
		return nil, err
	}

	// 启动 socket 文件监控 协程,监控套接字文件的变化，一旦检测到文件被删除，就通过通道传递错误信息。
	// 除了删除事件，其他事件都被忽略
	go func(l *UAPIListener) {
		var buf [0]byte

		// for 确保，只要监听到事件，就进入下次循环 重新确认文件是否存在
		for {
			defer uapi.inotifyRWCancel.Close()
			// start with lstat to avoid race condition
			// 开始时检查文件是否存在，避免竞争条件
			if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
				l.connErr <- err
				return
			}

			// 阻塞等待 inotify 事件通知
			_, err := uapi.inotifyRWCancel.Read(buf[:])
			if err != nil {
				l.connErr <- err
				return
			}
		}
	}(uapi)

	// watch for new connections
	// 启动另一个 goroutine 持续接受新的连接请求：

	// 调用 底层监听器的 Accept 方法 接受 wg 工具连接
	// 若发生错误，将错误通过通道传递并退出循环
	// 若成功接受连接，将连接对象通过通道传递给主程序处理
	go func(l *UAPIListener) {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				l.connErr <- err
				break
			}
			l.connNew <- conn
		}
	}(uapi)

	return uapi, nil
}
