//go:generate mkwinsyscall -output zlookupippoc.go lookupippoc.go
//sys getAddrInfoEx?(nodename *uint16, servicename *uint16, dwNameSpace uint32, lpNspId *uint16, hints *addrinfoexW, result **addrinfoexW, timeout uint32, o *overlapped, cr *uint16, ch *handle) (err error) = ws2_32.GetAddrInfoExW
//sys getAddrInfoExCancel(ch *handle) (err error) = ws2_32.GetAddrInfoExCancel
//sys freeAddrInfoEx(result *addrinfoexW) = ws2_32.FreeAddrInfoExW

// This is a proof of concept to see if using AddrinfoEx and Events is a good
// idea in the production net package for go. Feel free to use any and all
// code/ideas from this but do not assume that anything here is a good idea.
// The whole point behind this proof of concept is to experiment with a design
// before committing to doing the actual work to implement it in production.

//go:build windows && amd64
// +build windows,amd64

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Moved over to the main package just because I was playing. So we need to alias a
// bunch of things so the code looks more like it is in the production net package
type handle = windows.Handle
type overlapped = windows.Overlapped
type pointer = windows.Pointer
type guid = windows.GUID
type IPAddr = net.IPAddr
type DNSError = net.DNSError
type IP = net.IP

// Alias this function as well
var IPv4 = net.IPv4

var (
	errNoSuchHost = errors.New("no such host")
)

// The original sync version of lookupIP is here along with some routines
// shared between the sync and async versions.

// ipVersion returns the provided network's IP version: '4', '6' or 0
// if network does not end in a '4' or '6' byte.
func ipVersion(network string) byte {
	if network == "" {
		return 0
	}
	n := network[len(network)-1]
	if n != '4' && n != '6' {
		n = 0
	}
	return n
}

func winError(call string, err error) error {
	switch err {
	case windows.WSAHOST_NOT_FOUND:
		return errNoSuchHost
	}
	return os.NewSyscallError(call, err)
}

// Lazy implementation of acquireThread and releaseThread because
// the POC is about the async version

var tChan = make(chan struct{}, 500)

func acquireThread() {
	tChan <- struct{}{}
}
func releaseThread() {
	<-tChan
}

// The following is the original version of lookupIP complete with the
// original comments. This proof of concept was triggered by the comment
// in the select statement at the end of this function. The function
// lookupIPasync is my attempt to use AddrinfoExW and lpOverlapped.
// I don't know why that comment suggests three versions, as two seems
// right to me.
func lookupIPsync(ctx context.Context, network, name string) ([]IPAddr, error) {
	// TODO(bradfitz,brainman): use ctx more. See TODO below.

	var family int32 = syscall.AF_UNSPEC
	switch ipVersion(network) {
	case '4':
		family = syscall.AF_INET
	case '6':
		family = syscall.AF_INET6
	}

	getaddr := func() ([]IPAddr, error) {
		acquireThread()
		defer releaseThread()
		hints := syscall.AddrinfoW{
			Family:   family,
			Socktype: syscall.SOCK_STREAM,
			Protocol: syscall.IPPROTO_IP,
		}
		var result *syscall.AddrinfoW
		name16p, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			return nil, &DNSError{Name: name, Err: err.Error()}
		}
		e := syscall.GetAddrInfoW(name16p, nil, &hints, &result)
		if e != nil {
			err := winError("getaddrinfow", e)
			dnsError := &DNSError{Err: err.Error(), Name: name}
			if err == errNoSuchHost {
				dnsError.IsNotFound = true
			}
			return nil, dnsError
		}
		defer syscall.FreeAddrInfoW(result)
		addrs := make([]IPAddr, 0, 5)
		for ; result != nil; result = result.Next {
			addr := unsafe.Pointer(result.Addr)
			switch result.Family {
			case syscall.AF_INET:
				a := (*syscall.RawSockaddrInet4)(addr).Addr
				addrs = append(addrs, IPAddr{IP: IPv4(a[0], a[1], a[2], a[3])})
			case syscall.AF_INET6:
				a := (*syscall.RawSockaddrInet6)(addr).Addr
				zone := " " //zoneCache.name(int((*syscall.RawSockaddrInet6)(addr).Scope_id))
				addrs = append(addrs, IPAddr{IP: IP{a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]}, Zone: zone})
			default:
				return nil, &DNSError{Err: syscall.EWINDOWS.Error(), Name: name}
			}
		}
		return addrs, nil
	}

	type ret struct {
		addrs []IPAddr
		err   error
	}

	var ch chan ret
	if ctx.Err() == nil {
		ch = make(chan ret, 1)
		go func() {
			addr, err := getaddr()
			ch <- ret{addrs: addr, err: err}
		}()
	}

	select {
	case r := <-ch:
		return r.addrs, r.err
	case <-ctx.Done():
		// TODO(bradfitz,brainman): cancel the ongoing
		// GetAddrInfoW? It would require conditionally using
		// GetAddrInfoEx with lpOverlapped, which requires
		// Windows 8 or newer. I guess we'll need oldLookupIP,
		// newLookupIP, and newerLookUP.
		//
		// For now we just let it finish and write to the
		// buffered channel.
		return nil, &DNSError{
			Name:      name,
			Err:       ctx.Err().Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
}

// Here begins the code for the new async version.

// The async version AddrinfoExW has a different data structure from AddrinfoW
type addrinfoexW struct {
	Flags     int32
	Family    int32
	Socktype  int32
	Protocol  int32
	Addrlen   uintptr
	Canonname *uint16
	Addr      uintptr
	Blob      pointer
	Bloblen   uintptr
	Provider  *guid
	Next      *addrinfoexW
}

// Rather than have a single pool of 500 slots which is what the sync version
// has (see acquireThread()), the sync version has 3 pools with either 1 slice,
// 2 slices, or 5 slices of 64 slots. So the sync version can have (1+2+5)*64
// which is 512 lookups running concurrently.

var (
	initlookupIP sync.Once
	useAsync     bool
	evpoolSizes  = [3]int{1, 2, 5}
	evpoolChans  [3]chan reqstruct
	evpoolSlots  [3]chan struct{}
)

const _MAXIMUM_WAIT_OBJECTS = 64 // WaitForMultipleObjects max events to wait on

var impllookupIP func(ctx context.Context, network, name string) ([]IPAddr, error)

// Simple wrapper function that checks if FreeAddrInfoExW is defined. If so,
// we use the async version and if not we use the sync version.

func lookupIP(ctx context.Context, network, name string) ([]IPAddr, error) {

	initlookupIP.Do(func() {
		// One time initialization
		useAsync = (procFreeAddrInfoExW.Find() == nil)
		if useAsync { // Use AddrinfoExW
			impllookupIP = lookupIPasync
		} else {
			impllookupIP = lookupIPsync
		}
	})
	return impllookupIP(ctx, network, name)
}

func lookupIPasync(ctx context.Context, network, name string) ([]IPAddr, error) {
	// Get family
	var family int32 = syscall.AF_UNSPEC
	switch ipVersion(network) {
	case '4':
		family = syscall.AF_INET
	case '6':
		family = syscall.AF_INET6
	}
	// Get a free event,channel pair as well as the channel and index needed to free
	// the pair
	ev, fChan, rChan, evidx, everr := acquireEvent()
	if everr != nil {
		return nil, everr
	}
	// Can't use defer anymore because cancellation may cause return before event is freed
	// so be sure to check every exit to free the event channel pair as needed

	hints := addrinfoexW{
		Family:   family,
		Socktype: syscall.SOCK_STREAM,
		Protocol: syscall.IPPROTO_IP,
	}
	var result *addrinfoexW
	var o overlapped = overlapped{HEvent: ev}
	var cHandle handle
	name16p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		freeEvent(fChan, evidx)
		return nil, &DNSError{Name: name, Err: err.Error()}
	}

	e := getAddrInfoEx(name16p, nil, windows.NameDnsDomain, nil,
		&hints, &result, 0, &o, nil,
		&cHandle)

	if e != nil {
		err := winError("getaddrinfoexw", e)
		dnsError := &DNSError{Err: err.Error(), Name: name}
		if err == errNoSuchHost {
			dnsError.IsNotFound = true
		}
		freeEvent(fChan, evidx)
		return nil, dnsError
	}
	// The sync version has a defer here as well. Again, cancel causes an issue

	select {
	case <-rChan:
		// Lookup finished
		addrs := make([]IPAddr, 0, 5)
		for result := result; result != nil; result = result.Next {
			addr := unsafe.Pointer(result.Addr)
			switch result.Family {
			case syscall.AF_INET:
				a := (*syscall.RawSockaddrInet4)(addr).Addr
				addrs = append(addrs, IPAddr{IP: IPv4(a[0], a[1], a[2], a[3])})
			case syscall.AF_INET6:
				a := (*syscall.RawSockaddrInet6)(addr).Addr
				zone := " " //zoneCache.name(int((*syscall.RawSockaddrInet6)(addr).Scope_id))
				addrs = append(addrs, IPAddr{IP: IP{a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]}, Zone: zone})
			default:
				freeAddrInfoEx(result)
				freeEvent(fChan, evidx)
				return nil, &DNSError{Err: syscall.EWINDOWS.Error(), Name: name}
			}
		}
		freeAddrInfoEx(result)
		freeEvent(fChan, evidx)
		return addrs, nil
	case <-ctx.Done():
		// Need to cancel
		_ = getAddrInfoExCancel(&cHandle)
		go func() {
			<-rChan
			freeAddrInfoEx(result)
			freeEvent(fChan, evidx)
		}()
		return nil, &DNSError{
			Name:      name,
			Err:       ctx.Err().Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
}

var initevpool sync.Once

type poolstruct struct {
	wevent    handle        // the windows event handle needed to start the async operation
	compChan  chan struct{} // the go channel that gets the i/o completion
	weventidx int           // needed to free the event / channel pair
	everr     error         // in the remote case an error happens
}

type reqstruct struct {
	replyChan chan poolstruct // pass a channel here to request an event / channel pair
	weventidx int             // if replyChan is nil, this is the event / channel to free
}

// The async replacement for acquireThread. Besides just restricting the number of
// concurrent lookups happening, this function also returns an event handle (Windows),
// a channel to free the event and other info, a channel that gets a message when
// the event fires, the index of the event (needed for freeing) and an error
// indicator

func acquireEvent() (ev handle, fChan chan reqstruct, rChan chan struct{}, evidx int, everror error) {
	// On first time, create needed structures and start pool controllers
	initevpool.Do(func() {
		for i := range evpoolSlots {
			evpoolSlots[i] = make(chan struct{}, evpoolSizes[i]*_MAXIMUM_WAIT_OBJECTS)
			evpoolChans[i] = make(chan reqstruct, 1)
			go evpool(i)
		}
	})

	// The following code tries to use the lowest pools first but
	// if both the lowest two pools are full, it just waits for any
	// pool to have a free slot.

	var pool int
	select {
	case evpoolSlots[0] <- struct{}{}: // Try for lowest pool
		pool = 0
	default: // Lowest pool is full
		select {
		case evpoolSlots[0] <- struct{}{}: // Try for lowest pool
			pool = 0
		case evpoolSlots[1] <- struct{}{}: // Try for middle pool
			pool = 1
		default: // Lowest and Middle pool are full
			select {
			case evpoolSlots[0] <- struct{}{}:
				pool = 0
			case evpoolSlots[1] <- struct{}{}:
				pool = 1
			case evpoolSlots[2] <- struct{}{}:
				pool = 2
			} // No default clause so wait for any pool to have a slot
		}
	}

	// Ask the pool for an event / channel pair as well as the
	// index to free the pair when no longer needed

	rchan := make(chan poolstruct)
	evpoolChans[pool] <- reqstruct{replyChan: rchan, weventidx: 0}
	poolinfo := <-rchan
	return poolinfo.wevent, evpoolChans[pool], poolinfo.compChan, poolinfo.weventidx, poolinfo.everr
}

func freeEvent(fChan chan reqstruct, evidx int) {
	fChan <- reqstruct{replyChan: nil, weventidx: evidx}
}

func evpool(poolidx int) {
	evPoolChan := evpoolChans[poolidx]           // Incoming requests or free ops
	poolSize := evpoolSizes[poolidx]             // How many parallel waits this pool supports
	handles := make([][]handle, poolSize)        // One slice of events for each parallel wait
	evchans := make([][]chan struct{}, poolSize) // One slice of channels as well
	wchans := make([]chan bool, poolSize)        // A channel to control the evwait goroutines
	rflags := make([][]bool, poolSize)           // Flag showing if the event is in use
	acount := make([]int, poolSize)              // Number of events in use for each evwait
	needInit := true
	var err error
	for {
		reqinfo := <-evPoolChan
		if needInit {
			for i := 0; i < poolSize; i++ {
				handles[i] = make([]handle, _MAXIMUM_WAIT_OBJECTS)
				evchans[i] = make([]chan struct{}, _MAXIMUM_WAIT_OBJECTS)
				wchans[i] = make(chan bool)
				rflags[i] = make([]bool, _MAXIMUM_WAIT_OBJECTS)
				for j := range handles[i] {
					// Need to ask about error handling here
					// Also not freeing the event but process termination
					// does that so no need for runtime.setFinalizer
					handles[i][j], err = windows.CreateEvent(nil, 1, 0, nil)
					if err != nil {
						reqinfo.replyChan <- poolstruct{everr: &DNSError{Err: syscall.EWINDOWS.Error(), Name: "Initialization"}}
					}
					evchans[i][j] = make(chan struct{})
					rflags[i][j] = false
				}
				acount[i] = 0
				go evwait(wchans[i], handles[i], evchans[i])
			}
			needInit = false
		}
		if reqinfo.replyChan == nil { // Request to free the event channel pair
			// i is index to the evwait and j is the index to the event channel pair
			i, j := indextoij(reqinfo.weventidx)
			acount[i]--
			rflags[i][j] = false
			if acount[i] == 0 {
				// no events active in this evwait so don't wait on events
				wchans[i] <- false
			}
			<-evpoolSlots[poolidx]
		} else {
			// Use the earliest evwait that has a free event channel pair
			for sentreply, i := false, 0; !sentreply; i++ {
				if acount[i] == _MAXIMUM_WAIT_OBJECTS {
					continue
				}
				// Hmm, if acount is wrong, the following code will panic. Needs testing
				for j := 0; !sentreply; j++ {
					if !rflags[i][j] {
						rflags[i][j] = true
						sentindex := ijtoindex(i, j)
						reqinfo.replyChan <- poolstruct{wevent: handles[i][j],
							compChan: evchans[i][j], weventidx: sentindex}
						sentreply = true
						acount[i]++
						if acount[i] == 1 {
							// an event active so start waiting on events
							wchans[i] <- true
						}
					}
				}
			}
		}
	}
}

func indextoij(index int) (int, int) {
	i := index / _MAXIMUM_WAIT_OBJECTS
	j := index % _MAXIMUM_WAIT_OBJECTS
	return i, j
}

func ijtoindex(i int, j int) int {
	return (i * _MAXIMUM_WAIT_OBJECTS) + j
}

func evwait(cchan chan bool, handles []handle,
	rchans []chan struct{}) {
	waitactive := false
outerloop:
	for {
		if waitactive {
			ev, _ := windows.WaitForMultipleObjects(handles, false, 500)
			if ev < _MAXIMUM_WAIT_OBJECTS {
				_ = windows.ResetEvent(handles[ev])
				rchans[ev] <- struct{}{}
			}
		} else {
			waitactive = <-cchan
		}
		for {
			select {
			case waitactive = <-cchan:
			default:
				continue outerloop
			}
		}
	}
}

func main() {

	names := []string{"ServeSosna2.home.arpa", "bbc.com", "firewall.home.arpa"}

	for _, name := range names {
		addrs, error := lookupIP(context.Background(), "", name)
		fmt.Println("Results - ", addrs, "[", error, "]")
		addrs, error = lookupIP(context.Background(), "ipv4", name)
		fmt.Println("IPv4 Results - ", addrs, "[", error, "]")
		addrs, error = lookupIP(context.Background(), "ipv6", name)
		fmt.Println("IPv6 Results - ", addrs, "[", error, "]")
		addrs, error = lookupIPsync(context.Background(), "", name)
		fmt.Println("sync Results - ", addrs, "[", error, "]")
	}
}
