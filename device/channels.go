/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"runtime"
	"sync"
)

// An outboundQueue is a channel of QueueOutboundElements awaiting encryption.
// An outboundQueue is ref-counted using its wg field.
// An outboundQueue created with newOutboundQueue has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done to remove the initial reference.
// When the refcount hits 0, the queue's channel is closed.

// outboundQueue 是一个 channel，用于存放 等待加密的 QueueOutboundElements 元素
// 出站队列 通过其 wg 字段 进行引用计数。
// 使用 newOutboundQueue 创建的 outboundQueue 拥有一个引用。
// 每个新增的写入器都必须调用 wg.Add(1)。
// 每个完成的写入器必须调用 wg.Done()。
// 当不再有新的写入器 加入时，
// 调用 wg.Done 以移除初始引用。
// 当引用计数达到 0 时，队列的通道将被关闭。
type outboundQueue struct {
	c  chan *QueueOutboundElementsContainer
	wg sync.WaitGroup
}

func newOutboundQueue() *outboundQueue {
	q := &outboundQueue{
		c: make(chan *QueueOutboundElementsContainer, QueueOutboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A inboundQueue is similar to an outboundQueue; see those docs.
type inboundQueue struct {
	c  chan *QueueInboundElementsContainer
	wg sync.WaitGroup
}

func newInboundQueue() *inboundQueue {
	q := &inboundQueue{
		c: make(chan *QueueInboundElementsContainer, QueueInboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A handshakeQueue is similar to an outboundQueue; see those docs.
type handshakeQueue struct {
	c  chan QueueHandshakeElement
	wg sync.WaitGroup
}

func newHandshakeQueue() *handshakeQueue {
	q := &handshakeQueue{
		c: make(chan QueueHandshakeElement, QueueHandshakeSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

type autodrainingInboundQueue struct {
	c chan *QueueInboundElementsContainer
}

// newAutodrainingInboundQueue returns a channel that will be drained when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
func newAutodrainingInboundQueue(device *Device) *autodrainingInboundQueue {
	q := &autodrainingInboundQueue{
		c: make(chan *QueueInboundElementsContainer, QueueInboundSize),
	}
	runtime.SetFinalizer(q, device.flushInboundQueue)
	return q
}

func (device *Device) flushInboundQueue(q *autodrainingInboundQueue) {
	for {
		select {
		case elemsContainer := <-q.c:
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				device.PutMessageBuffer(elem.buffer)
				device.PutInboundElement(elem)
			}
			device.PutInboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

type autodrainingOutboundQueue struct {
	c chan *QueueOutboundElementsContainer
}

// newAutodrainingOutboundQueue returns a channel that will be drained when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
// All sends to the channel must be best-effort, because there may be no receivers.
func newAutodrainingOutboundQueue(device *Device) *autodrainingOutboundQueue {
	q := &autodrainingOutboundQueue{
		c: make(chan *QueueOutboundElementsContainer, QueueOutboundSize),
	}
	runtime.SetFinalizer(q, device.flushOutboundQueue)
	return q
}

func (device *Device) flushOutboundQueue(q *autodrainingOutboundQueue) {
	for {
		select {
		case elemsContainer := <-q.c:
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
			device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}
