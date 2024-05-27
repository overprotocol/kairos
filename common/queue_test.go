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

import (
	"reflect"
	"testing"
)

// TestEnqueue checks the functionality of the Enqueue method.
func TestEnqueue(t *testing.T) {
	q := NewQueue[int]()
	for i := 1; i <= 5; i++ {
		q.Enqueue(i)
	}
	expected := []int{1, 2, 3, 4, 5}
	if !reflect.DeepEqual(q.items, expected) {
		t.Errorf("Enqueue multiple failed, got %v, want %v", q.items, expected)
	}
}

// TestDequeue checks the functionality of the Dequeue method.
func TestDequeue(t *testing.T) {
	q := NewQueue[int]()
	for i := 1; i <= 5; i++ {
		q.Enqueue(i)
	}

	for i := 1; i <= 3; i++ {
		item, ok := q.Dequeue()
		if item != i || !ok {
			t.Errorf("Dequeue failed at step %d, got %v, want %v", i, item, i)
		}
	}

	expected := []int{4, 5}
	if !reflect.DeepEqual(q.items, expected) {
		t.Errorf("After multiple dequeues, queue state is incorrect, got %v, want %v", q.items, expected)
	}
}

// TestEnqueueDequeueSequence tests a sequence of enqueue and dequeue operations.
func TestEnqueueDequeueSequence(t *testing.T) {
	q := NewQueue[int]()
	sequence := []int{1, 2, 3, 4, 5}
	for _, num := range sequence {
		q.Enqueue(num)
	}
	q.Dequeue() // Dequeue 1
	q.Dequeue() // Dequeue 2
	q.Enqueue(6)
	q.Enqueue(7)

	expected := []int{3, 4, 5, 6, 7}
	if !reflect.DeepEqual(q.items, expected) {
		t.Errorf("Enqueue-Dequeue sequence failed, got %v, want %v", q.items, expected)
	}
}

// TestIsEmpty checks the functionality of the IsEmpty method.
func TestIsEmpty(t *testing.T) {
	q := NewQueue[int]()
	if !q.IsEmpty() {
		t.Errorf("IsEmpty failed, expected true, got false")
	}
	q.Enqueue(1)
	if q.IsEmpty() {
		t.Errorf("IsEmpty failed, expected false, got true")
	}
}

// TestSize checks the functionality of the Size method.
func TestSize(t *testing.T) {
	q := NewQueue[int]()
	q.Enqueue(1)
	q.Enqueue(2)
	if q.Size() != 2 {
		t.Errorf("Size failed, expected 2, got %d", q.Size())
	}
}

// TestPeek checks the functionality of the Peek method.
func TestPeek(t *testing.T) {
	q := NewQueue[int]()
	q.Enqueue(1)
	item, ok := q.Peek()
	if item != 1 || !ok {
		t.Errorf("Peek failed, expected 1 and true, got %v and %v", item, ok)
	}
	// Test peek on empty queue
	q = NewQueue[int]()
	item, ok = q.Peek()
	if item != 0 || ok {
		t.Errorf("Peek on empty queue failed, expected 0 and false, got %v and %v", item, ok)
	}
}
