package ctl

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"
)

import "golang.org/x/sys/unix"

type Opcode uint32

const (
	OpcodeAuthenticate Opcode = 1
	OpcodeGetRoot      Opcode = 2
	OpcodeIoctl        Opcode = 3
)

type fmacUidCap struct {
	uid  uint32
	_    [4]byte // padding to align caps to 8
	caps uint64
}

type fmacSepolicyRule struct {
	src    [64]byte
	tgt    [64]byte
	cls    [64]byte
	perm   [64]byte
	effect int32
	invert int32
}

const magic = 'F'

func _IO(nr uint32) uint32                { return (magic << 8) | nr }
func _IOW(nr uint32, size uint32) uint32  { return 0x40000000 | (size << 16) | (magic << 8) | nr }
func _IOR(nr uint32, size uint32) uint32  { return 0x80000000 | (size << 16) | (magic << 8) | nr }
func _IOWR(nr uint32, size uint32) uint32 { return 0xC0000000 | (size << 16) | (magic << 8) | nr }

var (
	IOC_GET_SHM      = _IO(0)
	IOC_BIND_EVT     = _IOW(1, 4)
	IOC_CHK_WRITE    = _IOR(2, 4)
	IOC_ADD_UID      = _IOW(3, 4)
	IOC_DEL_UID      = _IOW(4, 4)
	IOC_HAS_UID      = _IOWR(5, 4)
	IOC_SET_CAP      = _IOW(6, uint32(unsafe.Sizeof(fmacUidCap{})))
	IOC_GET_CAP      = _IOWR(7, uint32(unsafe.Sizeof(fmacUidCap{})))
	IOC_DEL_CAP      = _IOW(8, uint32(unsafe.Sizeof(fmacUidCap{})))
	IOC_SEL_ADD_RULE = _IOW(9, uint32(unsafe.Sizeof(fmacSepolicyRule{})))
)

func ioctl(fd int, cmd uint32, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(cmd), arg)
	if errno != 0 {
		return fmt.Errorf("ioctl errno=%d", errno)
	}
	return nil
}

func prctl1(op uint32) (int, error) {
	rop := uintptr(op + 200)
	r, _, errno := syscall.Syscall(syscall.SYS_PRCTL, rop, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

func Ctl(code Opcode) error {
	switch code {
	case OpcodeAuthenticate, OpcodeGetRoot, OpcodeIoctl:
		_, err := prctl1(uint32(code))
		return err
	default:
		return fmt.Errorf("unknown opcode: %d", code)
	}
}

func AddUid(fd int, uid int) error {
	if uid < 0 {
		return fmt.Errorf("invalid uid")
	}
	val := uint32(uid)
	return ioctl(fd, IOC_ADD_UID, uintptr(unsafe.Pointer(&val)))
}

func DelUid(fd int, uid int) error {
	if uid < 0 {
		return fmt.Errorf("invalid uid")
	}
	val := uint32(uid)
	return ioctl(fd, IOC_DEL_UID, uintptr(unsafe.Pointer(&val)))
}

func HasUid(fd int, uid int) (bool, error) {
	if uid < 0 {
		return false, fmt.Errorf("invalid uid")
	}
	val := uint32(uid)
	if err := ioctl(fd, IOC_HAS_UID, uintptr(unsafe.Pointer(&val))); err != nil {
		return false, err
	}
	return val != 0, nil
}

func SetCap(fd int, uid int, caps uint64) error {
	uc := fmacUidCap{uid: uint32(uid), caps: caps}
	return ioctl(fd, IOC_SET_CAP, uintptr(unsafe.Pointer(&uc)))
}

func GetCap(fd int, uid int) (uint64, error) {
	uc := fmacUidCap{uid: uint32(uid)}
	if err := ioctl(fd, IOC_GET_CAP, uintptr(unsafe.Pointer(&uc))); err != nil {
		return 0, err
	}
	return uc.caps, nil
}

func DelCap(fd int, uid int) error {
	uc := fmacUidCap{uid: uint32(uid)}
	return ioctl(fd, IOC_DEL_CAP, uintptr(unsafe.Pointer(&uc)))
}

func AddSelinuxRule(fd int, src, tgt, cls, perm string, effect int, invert bool) error {
	var r fmacSepolicyRule
	copyStr := func(dst *[64]byte, s string) {
		n := copy(dst[:], s)
		if n < 64 {
			dst[n] = 0
		}
	}
	copyStr(&r.src, src)
	copyStr(&r.tgt, tgt)
	copyStr(&r.cls, cls)
	copyStr(&r.perm, perm)
	r.effect = int32(effect)
	if invert {
		r.invert = 1
	}
	return ioctl(fd, IOC_SEL_ADD_RULE, uintptr(unsafe.Pointer(&r)))
}

func ScanDriverFd() (int, error) {
	return scanFdByLink("[fmac_shm]")
}

func ScanCtlFd() (int, error) {
	return scanFdByLink("[fmac_ctl]")
}

func scanFdByLink(target string) (int, error) {
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		return -1, err
	}
	defer dir.Close()

	entries, err := dir.Readdirnames(-1)
	if err != nil {
		return -1, err
	}

	for _, name := range entries {
		fdNum, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		link, err := os.Readlink(filepath.Join("/proc/self/fd", name))
		if err != nil {
			continue
		}
		if contains(link, target) {
			return fdNum, nil
		}
	}
	return -1, fmt.Errorf("fd not found: %s", target)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

type Event struct {
	fd int
}

func NewEvent() (Event, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, 0, syscall.O_CLOEXEC, 0)
	if errno != 0 {
		return Event{}, errno
	}
	return Event{fd: int(fd)}, nil
}

func (e Event) Close() {
	syscall.Close(e.fd)
}

func (e Event) Wait() (uint64, error) {
	pfd := []unix.PollFd{
		{Fd: int32(e.fd), Events: unix.POLLIN},
	}
	for {
		n, err := unix.Poll(pfd, -1)
		if err != nil || n <= 0 {
			continue
		}
		var val uint64
		buf := (*[8]byte)(unsafe.Pointer(&val))
		nr, err := unix.Read(e.fd, buf[:])
		if err != nil || nr != 8 {
			continue
		}
		return val, nil
	}
}

func (e Event) WaitTimeout(timeoutMs int) (int64, error) {
	pfd := []unix.PollFd{
		{Fd: int32(e.fd), Events: unix.POLLIN},
	}

	n, err := unix.Poll(pfd, timeoutMs)
	if err != nil || n <= 0 {
		return -1, err
	}

	var val uint64
	buf := (*[8]byte)(unsafe.Pointer(&val))
	nr, err := unix.Read(e.fd, buf[:])
	if err != nil || nr != 8 {
		return -1, fmt.Errorf("read error")
	}
	return int64(val), nil
}
