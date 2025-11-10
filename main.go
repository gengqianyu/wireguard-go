//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"             // file descriptor of TUN device
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"            // file descriptor of UAPI socket
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND" // run in foreground
)

func printUsage() {
	fmt.Printf("Usage: %s [-f/--foreground] INTERFACE-NAME\n", os.Args[0])
}

func warning() {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		if os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
			return
		}
	default:
		return
	}

	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│   Warning:                                           │")
	fmt.Fprintln(os.Stderr, "│   Running wireguard-go is not required because this  │")
	fmt.Fprintln(os.Stderr, "│   kernel has first class support for WireGuard. For  │")
	fmt.Fprintln(os.Stderr, "│   information on installing the kernel module,       │")
	fmt.Fprintln(os.Stderr, "│   please visit:                                      │")
	fmt.Fprintln(os.Stderr, "│         https://www.wireguard.com/install/           │")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────┘")
}

// sudo LOG_LEVEL=debug go run . -f utun9
func main() {
	// handle --version flag
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("wireguard-go v%s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <Jason@zx2c4.com>.\n", Version, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

	var foreground bool      // run in foreground
	var interfaceName string // name of TUN interface
	if len(os.Args) < 2 || len(os.Args) > 3 {
		printUsage() // print usage and exit
		return
	}

	switch os.Args[1] {

	case "-f", "--foreground":
		foreground = true // run in foreground
		if len(os.Args) != 3 {
			printUsage()
			return
		}
		interfaceName = os.Args[2] // get interface name from command line argument

	default:
		foreground = false
		if len(os.Args) != 2 {
			printUsage()
			return
		}
		interfaceName = os.Args[1]
	}

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	// get log level (default: info)
	// valid levels: silent, error, verbose, debug
	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()

	// open TUN device (or use supplied fd)
	// 创建 或 从已提供的文件描述符初始化 TUN 虚拟网络设备
	// TUN 设备是一种虚拟网络设备，允许 用户空间程序 直接读写 IP 数据包
	// 这是 WireGuard 实现 VPN 隧道功能的核心组件之一
	tunDevice, err := func() (tun.Device, error) {
		// 从环境变量中获取 TUN 文件描述符
		tunFdStr := os.Getenv(ENV_WG_TUN_FD) // get TUN fd from environment variable

		// 如果环境变量中 没有提供文件描述符，则创建新的 TUN 设备
		if tunFdStr == "" {
			// CreateTUN 函数 会根据不同平台创建相应的 TUN 设备
			// 第一个参数是 接口名称，第二个参数是 MTU（最大传输单元）大小
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd
		// 将字符串形式的 文件描述符 转换为整数
		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		// 将 文件描述符 设置为 非阻塞模式
		// 非阻塞模式 允许 I/O 操作 在无法立即完成时返回错误，而不是阻塞等待
		err = unix.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		// 基于 文件描述符 创建一个 os.File 对象
		// 这是为了在 Go 语言层面 操作该文件描述符
		file := os.NewFile(uintptr(fd), "")

		// 如果存在设备直接使用 已有的 文件描述符创建 TUN 设备
		// CreateTUNFromFile 会基于已有的文件描述符初始化 TUN 设备结构
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	// 获取真实的网卡接口名称
	// 某些平台上，实际创建的 TUN 设备名称可能与请求的不同
	// 例如在 macOS 上，TUN 设备通常命名为 utunX 格式
	if err == nil {
		realInterfaceName, err2 := tunDevice.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}
	// 设置日志记录器
	// 使用接口名称 作为日志前缀，方便多设备环境下的日志识别
	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Verbosef("Starting wireguard-go version %s", Version)

	// 检查 TUN 设备创建是否成功
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	// wireguard-go 进程启动时会创建一个 UAPI 文件
	// （例如 /var/run/wireguard/wg0.sock，
	// 其中 wg0 是 WireGuard 接口名）；
	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			// create new UAPI socket
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()

	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tunDevice.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to determine executable: %v", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Errorf("Failed to daemonize: %v", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	// 创建 WireGuard device 实例, 这里面会启动 UDP 端口监听，用于 接收和发送加密的 VPN 流量
	// 参数 conn.NewDefaultBind() 会创建一个 默认的 绑定接口 实例，也就是 StdNetBind 实例
	// UDP 端口监听其实是在 StdNetBind.Open 方法中实现的，这里就是一个 device 和 conn 关联起来
	// conn 监听在指定的 UDP 端口上，收到加密的 VPN 流量后，会通过 device 处理(加解密)后，发送到 TUN 虚拟网卡
	// NewDevice 函数最后会启动 device 的 worker 携程 去具体处理 进/出 队列中的数据
	device := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	logger.Verbosef("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	// 创建 UAPI 监听器，用于 wg 命令行工具等外部程序 与 wireguard-go 进程进行通信
	UAPIListener, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	// 接收
	go func() {
		for {
			// 从 UAPIListener.connNew 通道中接收 新的连接请求
			conn, err := UAPIListener.Accept()
			if err != nil {
				errs <- err
				return
			}

			// 启动一个新的协程，处理该 socket 连接
			// 处理 wg 命令行工具发起的各种配置请求，包括重新绑定 UDP 端口等
			go device.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	// wait for program to terminate
	// 监听操作系统信号
	// 包括 TERM、INT（Ctrl+C） 等
	// 当收到这些信号时，会触发程序退出

	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	UAPIListener.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}
