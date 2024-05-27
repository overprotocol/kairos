// Copyright 2024 The kairos Authors
// This file is part of the kairos library.
//
// The kairos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The kairos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the kairos library. If not, see <http://www.gnu.org/licenses/>.

package common

// Queue represents a queue that holds any type.
type Queue[T any] struct {
	items []T
}

// NewQueue creates a new queue.
func NewQueue[T any]() *Queue[T] {
	return &Queue[T]{}
}

// Enqueue adds a value at the end of the queue.
func (q *Queue[T]) Enqueue(value T) {
	q.items = append(q.items, value)
}

// Dequeue removes a value at the front of the queue and returns it.
// If the queue is empty, it returns the zero value of the type and a boolean flag as false.
func (q *Queue[T]) Dequeue() (T, bool) {
	if len(q.items) == 0 {
		var zeroValue T // Create a zero value of the type T
		return zeroValue, false
	}
	item := q.items[0]
	q.items = q.items[1:]
	return item, true
}

func (q *Queue[T]) IsEmpty() bool {
	return len(q.items) == 0
}

func (q *Queue[T]) Size() int {
	return len(q.items)
}

func (q *Queue[T]) Peek() (T, bool) {
	if len(q.items) == 0 {
		var zeroValue T // Create a zero value of the type T
		return zeroValue, false
	}
	return q.items[0], true
}
