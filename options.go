package ipv4

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Ver= 4 |IHL= 8 |Type of Service|       Total Length = 576      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       Identification = 111    |Flg=0|     Fragment Offset = 0 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Time = 123  |  Protocol = 6 |       Header Checksum         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        source address                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      destination address                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Opt. Code = x | Opt.  Len.= 3 | option value  | Opt. Code = x |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Opt. Len. = 4 |           option value        | Opt. Code = 1 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Opt. Code = y | Opt. Len. = 3 |  option value | Opt. Code = 0 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             data                              |
// \                                                               \
// \                                                               \
// |                             data                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             data                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                 Example of datagram with options
//

// The option-type octet is viewed as having 3 fields:
// 1 bit   copied flag,
// 2 bits  option class,
// 5 bits  option number.
type OptionType struct {
	Value uint8
}

func (ot *OptionType) Copied() uint8 {
	return ot.Value >> 7
}

func (ot *OptionType) Class() uint8 {
	return (ot.Value >> 5) & 3
}

func (ot *OptionType) Number() uint8 {
	return ot.Value & 31
}

// The option field is variable in length.  There may be zero or more
// options.  There are two cases for the format of an option:
//
//	Case 1:  A single octet of option-type.
//	Case 2:  An option-type octet, an option-length octet, and the actual option-data octets.
//
// Option value length = option length - 2 bytes (type and length fields)
type Option struct {
	Type   OptionType
	Length uint8
	Value  []byte
}

func (o *Option) Marshal() []byte {
	if o.Type.Number() == 0 || o.Type.Number() == 1 {
		return []byte{o.Type.Value}
	}

	return append([]byte{o.Type.Value, o.Length}, o.Value[:o.Length-2]...)
}

func (o *Option) Unmarshal(b []byte) {
	if len(b) == 0 {
		return
	}

	o.Type.Value = b[0]

	if o.Type.Number() == 0 || o.Type.Number() == 1 {
		return
	}

	if len(b) >= 2 {
		o.Length = b[1]
		o.Value = b[2:o.Length]
	}
}
