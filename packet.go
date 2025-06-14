package ipv4

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// combine version and IHL in one byte
// -0-1-2-3-4-5-6-7-
// |Version|  IHL  |
type VersionIHL struct {
	Value uint8
}

func (v *VersionIHL) Version() uint8 {
	return v.Value >> 4
}

// -0-1-2-3-4-5-6-7-   -0-1-2-3-4-5-6-7-    -0-1-2-3-4-5-6-7-
// |1 1 1 1|1 1 1 1| & |0 0 0 0|1 1 1 1| => |0 0 0 0|1 1 1 1|
func (v *VersionIHL) IHL() uint8 {
	return v.Value & 15
}

// combine flags and fragment offset fields in two bytes
// -0-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-
// |Flags|        Fragment Offset        |
type FlagsFrOffset struct {
	Value uint16
}

func (f *FlagsFrOffset) Flags() uint16 {
	return f.Value >> 13
}

func (f *FlagsFrOffset) FragmentOffset() uint16 {
	return f.Value & 0x1FFF
}

type IPAddr [4]byte

func (i *IPAddr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3])
}

func (i *IPAddr) Bytes() []byte {
	return i[:]
}

// Parse IPv4 addr from format "a.b.c.d"
func IPFromString(addr string) (IPAddr, error) {
	splitted := strings.Split(addr, ".")
	if len(splitted) != 4 {
		return IPAddr{}, fmt.Errorf("wrong ip address")
	}

	var a, b, c, d int
	var err error

	a, err = strconv.Atoi(splitted[0])
	if err != nil {
		return IPAddr{}, fmt.Errorf("failed to parse ip addr: %w", err)
	}

	b, err = strconv.Atoi(splitted[1])
	if err != nil {
		return IPAddr{}, fmt.Errorf("failed to parse ip addr: %w", err)
	}

	c, err = strconv.Atoi(splitted[2])
	if err != nil {
		return IPAddr{}, fmt.Errorf("failed to parse ip addr: %w", err)
	}

	d, err = strconv.Atoi(splitted[3])
	if err != nil {
		return IPAddr{}, fmt.Errorf("failed to parse ip addr: %w", err)
	}

	return IPAddr{byte(a), byte(b), byte(c), byte(d)}, nil
}

func IPFromBytes(b []byte) (IPAddr, error) {
	if len(b) != 4 {
		return IPAddr{}, fmt.Errorf("wrong ip length")
	}

	return IPAddr{b[0], b[1], b[2], b[3]}, nil
}

const ipHeaderLength = 20

// Describe IP datagram from RFC791  https://datatracker.ietf.org/doc/html/rfc791
type Packet struct {
	VerIHL   VersionIHL // combine Version and IHL fields
	TOS      uint8
	Length   uint16
	ID       uint16
	FlFrOff  FlagsFrOffset // combine Flags and Fragment Offset fields
	TTL      uint8
	Protocol uint8
	Checksum uint16
	Src      IPAddr
	Dst      IPAddr

	Data    []byte
	Options []Option
}

func New(src, dst IPAddr, data []byte) *Packet {
	p := &Packet{
		VerIHL:   VersionIHL{Value: 0x45},
		TOS:      0,
		Length:   uint16(ipHeaderLength + len(data)),
		ID:       0,
		FlFrOff:  FlagsFrOffset{Value: 0},
		TTL:      64,
		Protocol: 6,
		Src:      src,
		Dst:      dst,
		Data:     data,
	}

	return p
}

func (p *Packet) WithOptions(opts ...Option) *Packet {
	p.Options = append(p.Options, opts...)

	return p
}

func (p *Packet) Marshal() []byte {
	options := p.marshalOptions() // first of all we marshal options

	p.Length += uint16(len(options)) // we need to recalculate length with options

	buf := make([]byte, len(p.Data)+ipHeaderLength+len(options)) // create buffer for whole packet

	// start to fill required fields
	buf[0] = p.VerIHL.Value
	buf[1] = p.TOS
	binary.BigEndian.PutUint16(buf[2:4], p.Length)
	binary.BigEndian.PutUint16(buf[4:6], p.ID)
	binary.BigEndian.PutUint16(buf[6:8], p.FlFrOff.Value)
	buf[8] = p.TTL
	buf[9] = p.Protocol
	copy(buf[12:16], p.Src[:])
	copy(buf[16:20], p.Dst[:])

	// copy options bytes
	copy(buf[20:20+len(options)], options[:])

	// copy payload bytes
	copy(buf[20+len(options):], p.Data)

	// recalculate checksum
	p.Checksum = p.CalculateChecksum(buf[:20+len(options)])
	binary.BigEndian.PutUint16(buf[10:12], p.Checksum)

	return buf
}

func (p *Packet) marshalOptions() []byte {
	buf := make([]byte, 0, len(p.Options)*3)

	for _, opt := range p.Options {
		buf = append(buf, opt.Marshal()...)
	}

	// append padding to 32 bit words
	if len(buf)%4 != 0 {
		for len(buf)%4 != 3 {
			opt := Option{Type: OptionType{0b00000001}} // No Operation option
			buf = append(buf, opt.Marshal()...)
		}

		eool := Option{Type: OptionType{0b00000000}} // End Of Option list
		buf = append(buf, eool.Marshal()...)
	}

	// we have to change IHL field
	p.VerIHL.Value += uint8(len(buf) / 4)

	return buf
}

func (p *Packet) Unmarshal(data []byte) {
	if len(data) < ipHeaderLength {
		return
	}

	p.VerIHL = VersionIHL{Value: data[0]}
	p.TOS = data[1]
	p.Length = binary.BigEndian.Uint16(data[2:4])
	p.ID = binary.BigEndian.Uint16(data[4:6])
	p.FlFrOff = FlagsFrOffset{Value: binary.BigEndian.Uint16(data[6:8])}
	p.TTL = data[8]
	p.Protocol = data[9]
	p.Checksum = binary.BigEndian.Uint16(data[10:12])

	p.Src, _ = IPFromBytes(data[12:16])
	p.Dst, _ = IPFromBytes(data[16:20])

	p.unmarshalOptions(data)

	p.Data = data[p.VerIHL.IHL()*4:]
}

func (p *Packet) unmarshalOptions(data []byte) {
	if p.VerIHL.IHL()*4 == ipHeaderLength {
		return
	}

	optionsNotEmpty := true
	pointer := 20

	for optionsNotEmpty {
		opt := Option{}

		if data[pointer]&31 == 0 || data[pointer]&31 == 1 {
			opt.Unmarshal(data[pointer : pointer+1])
			p.Options = append(p.Options, opt)
			pointer++

			if opt.Type.Number() == 0 {
				optionsNotEmpty = false
			}
		} else {
			length := data[pointer+1]
			opt.Unmarshal(data[pointer : pointer+int(length)])
			p.Options = append(p.Options, opt)

			pointer += int(length)
		}

		if pointer == int(p.VerIHL.IHL()*4) {
			optionsNotEmpty = false
		}
	}
}

func (p *Packet) CalculateChecksum(data []byte) uint16 {
	var sum uint32
	size := 20

	for i := 0; i < -1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if size&1 != 0 {
		sum += uint32(data[size-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^(uint16(sum))
}
