package kmod

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// kptr_restrict management

var (
	recordKptr byte
	kptrInited bool
	kptrPath   = "/proc/sys/kernel/kptr_restrict"
)

func kptrSet(code byte) error {
	f, err := os.OpenFile(kptrPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 1)
	if _, err := f.Read(buf); err != nil {
		return err
	}
	recordKptr = buf[0]
	kptrInited = true

	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	_, err = f.Write([]byte{code})
	return err
}

func kptrReset() {
	if !kptrInited {
		return
	}
	f, err := os.OpenFile(kptrPath, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write([]byte{recordKptr})
}

// symbol name normalization

func normalizeSymbol(sym string) string {
	if i := strings.Index(sym, "$"); i >= 0 {
		return sym[:i]
	}
	if i := strings.Index(sym, ".llvm."); i >= 0 {
		return sym[:i]
	}
	return sym
}

// /proc/kallsyms parser

func parseKallsyms() (map[string]uint64, error) {
	if err := kptrSet('1'); err != nil {
		return nil, fmt.Errorf("kptr_set: %w", err)
	}
	defer kptrReset()

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]uint64, 400000)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) < 3 {
			continue
		}
		addr, ok := hexToU64(fields[0])
		if !ok {
			continue
		}
		name := fields[2]
		m[name] = addr
	}
	return m, scanner.Err()
}

func hexToU64(s string) (uint64, bool) {
	if len(s) > 16 {
		return 0, false
	}
	var v uint64
	for _, c := range []byte(s) {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= uint64(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// ELF patching + insmod

func patchAndLoad(path string, kallsyms map[string]uint64) error {
	image, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read module: %w", err)
	}

	f, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		return fmt.Errorf("parse elf: %w", err)
	}
	defer f.Close()

	if f.Class != elf.ELFCLASS64 {
		return fmt.Errorf("only ELF64 supported")
	}

	// Find SHT_SYMTAB
	var symSection *elf.Section
	for _, s := range f.Sections {
		if s.Type == elf.SHT_SYMTAB {
			symSection = s
			break
		}
	}
	if symSection == nil {
		return fmt.Errorf("no SYMTAB section")
	}

	strSection := f.Sections[symSection.Link]
	strData, err := strSection.Data()
	if err != nil {
		return fmt.Errorf("read strtab: %w", err)
	}

	symData, err := symSection.Data()
	if err != nil {
		return fmt.Errorf("read symtab: %w", err)
	}

	const sym64Size = 24 // sizeof(Elf64_Sym)
	symCount := len(symData) / sym64Size

	for i := 0; i < symCount; i++ {
		off := i * sym64Size
		sym := symData[off : off+sym64Size]

		nameIdx := binary.LittleEndian.Uint32(sym[0:4])
		shndx := binary.LittleEndian.Uint16(sym[6:8])

		if shndx != uint16(elf.SHN_UNDEF) || nameIdx == 0 {
			continue
		}
		if int(nameIdx) >= len(strData) {
			continue
		}

		rawName := cstring(strData[nameIdx:])
		name := normalizeSymbol(rawName)

		addr, ok := kallsyms[name]
		if !ok {
			return fmt.Errorf("missing symbol: %s", name)
		}
		if addr == 0 {
			return fmt.Errorf("symbol %s has address 0", name)
		}

		fmt.Printf("Patching symbol %s -> 0x%x\n", name, addr)

		// patch st_value (offset 8, 8 bytes) and st_shndx (offset 6, 2 bytes)
		binary.LittleEndian.PutUint64(sym[8:16], addr)
		binary.LittleEndian.PutUint16(sym[6:8], uint16(elf.SHN_ABS))

		// write back into image
		// sym slice points into symData, need to find offset in image
		// We'll patch image directly using section offset
		imgOff := int(symSection.Offset) + off
		copy(image[imgOff:], sym)
	}

	return loadModule(image)
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func loadModule(image []byte) error {
	params := []byte("\x00")
	ret, _, errno := syscall.Syscall(
		syscall.SYS_INIT_MODULE,
		uintptr(unsafe.Pointer(&image[0])),
		uintptr(len(image)),
		uintptr(unsafe.Pointer(&params[0])),
	)
	if int(ret) < 0 || errno != 0 {
		return fmt.Errorf("init_module failed: errno=%d", errno)
	}
	return nil
}

// Load is the public entry point

func Load(path string) error {
	kallsyms, err := parseKallsyms()
	if err != nil {
		return fmt.Errorf("kallsyms: %w", err)
	}
	return patchAndLoad(path, kallsyms)
}
