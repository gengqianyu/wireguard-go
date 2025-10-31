/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1420

// 专门负责监听并处理 TUN 设备的各种事件。
// 该函数作为一个长期运行的 goroutine，是 WireGuard 设备状态管理 和 网络参数更新 的关键组件。
func (device *Device) RoutineTUNEventReader() {
	device.log.Verbosef("Routine: event worker - started")

	// 事件通道监听：通过 device.tun.device.Events() 获取 TUN 设备事件的通道，并在 for-range 循环中持续监听
	for event := range device.tun.device.Events() {

		// 事件检测：使用位运算检查事件是否包含 tun.EventMTUUpdate（MTU 更新事件）
		if event&tun.EventMTUUpdate != 0 {

			// MTU 获取：调用 device.tun.device.MTU() 获取更新后的 MTU 值
			mtu, err := device.tun.device.MTU()
			if err != nil {
				device.log.Errorf("Failed to load updated MTU of device: %v", err)
				continue
			}

			// 处理获取 MTU 失败的情况，记录错误日志并跳过后续处理
			// 拒绝负数 MTU 值，记录错误日志并跳过后续处理
			if mtu < 0 {
				device.log.Errorf("MTU not updated to negative value: %v", mtu)
				continue
			}

			var tooLarge string

			// MTU 限制：如果 MTU 超过 MaxContentSize，将其限制为最大值并记录提示信息
			if mtu > MaxContentSize {
				tooLarge = fmt.Sprintf(" (too large, capped at %v)", MaxContentSize)
				mtu = MaxContentSize
			}

			// 原子更新：使用 device.tun.mtu.Swap(int32(mtu)) 原子地更新设备的 MTU 值，确保并发安全
			old := device.tun.mtu.Swap(int32(mtu))
			if int(old) != mtu {
				device.log.Verbosef("MTU updated: %v%s", mtu, tooLarge)
			}
		}

		// 启动设备
		if event&tun.EventUp != 0 {
			device.log.Verbosef("Interface up requested")
			device.Up()
		}

		// 关闭设备
		if event&tun.EventDown != 0 {
			device.log.Verbosef("Interface down requested")
			device.Down()
		}
	}

	device.log.Verbosef("Routine: event worker - stopped")
}
