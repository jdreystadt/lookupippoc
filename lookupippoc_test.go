package main

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestAcquireEvent(t *testing.T) {
	a, b, c, d, everr := acquireEvent()
	if a == 0 {
		t.Fatalf("Invalid Response for event")
	}
	if b == nil || c == nil {
		t.Fatalf("Invalid response for a channel")
	}
	if d < 0 || d > 511 {
		t.Fatalf("Invalid response for event index")
	}
	if everr != nil {
		t.Fatalf("Error: %s", everr.Error())
	}
	freeEvent(b, d)
}

func Test1Event(t *testing.T) {
	a, b, c, d, everr := acquireEvent()
	if everr != nil {
		t.Fatalf("Error: %s", everr.Error())
	}
	err := windows.SetEvent(a)
	if err != nil {
		t.Fatalf("Error on SetEvent")
	}
	select {
	case <-c:
		freeEvent(b, d)
	case <-time.After(time.Second * 1):
		t.Fatalf("Timeout")
	}
	time.Sleep(time.Millisecond * time.Duration(1000))
}

var sleepdur = []int{5, 3, 8, 2, 5, 7, 1, 9, 9, 2}

func Test10Events(t *testing.T) {
	countdown := 10
	rchan := make(chan int)
	for i := 0; i < countdown; i++ {
		go eventtest(i, rchan)
	}
	for count := 0; count < countdown; count++ {
		goodtest := <-rchan
		if goodtest > 1000 {
			t.Fatalf("Timeout")
		}
	}
	time.Sleep(time.Millisecond * time.Duration(1000))
}

func Test100Events(t *testing.T) {
	countdown := 100
	rchan := make(chan int)
	for i := 0; i < countdown; i++ {
		go eventtest(i, rchan)
	}
	for count := 0; count < countdown; count++ {
		goodtest := <-rchan
		if goodtest > 1000 {
			t.Fatalf("Timeout")
		}
	}
	time.Sleep(time.Millisecond * time.Duration(100))
}

func Test1000Events(t *testing.T) {
	countdown := 1000
	rchan := make(chan int)
	for i := 0; i < countdown; i++ {
		go eventtest(i, rchan)
	}
	for count := 0; count < countdown; count++ {
		goodtest := <-rchan
		if goodtest > 1000 {
			t.Fatalf("Timeout")
		}
	}
	time.Sleep(time.Millisecond * time.Duration(1000))
}

func Test100EventsAgain(t *testing.T) {
	countdown := 100
	rchan := make(chan int)
	for i := 0; i < countdown; i++ {
		go eventtest(i, rchan)
	}
	for count := 0; count < countdown; count++ {
		goodtest := <-rchan
		if goodtest > 1000 {
			t.Fatalf("Timeout")
		}
	}
	time.Sleep(time.Millisecond * time.Duration(100))
}

func eventtest(i int, rchan chan int) {
	a, b, c, d, _ := acquireEvent()
	time.Sleep(time.Millisecond * time.Duration(10*sleepdur[i%len(sleepdur)]))
	_ = windows.SetEvent(a)
	select {
	case <-c:
		rchan <- d
	case <-time.After(time.Second * 5):
		rchan <- d + 1000
	}
	freeEvent(b, d)
}
