package ipv4

import (
	"fmt"
	"testing"
)

func Test_VersionIHL_GetVersion(t *testing.T) {
	tests := []struct {
		name     string
		verIHL   VersionIHL
		expected uint8
	}{
		{
			name:     "Get version",
			verIHL:   VersionIHL{Value: 79},
			expected: 4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := test.verIHL.Version()

			if val != test.expected {
				t.Errorf("Version not expected %d", val)
			}
		})
	}
}

func Test_VersionIHL_GetIHL(t *testing.T) {
	tests := []struct {
		name     string
		verIHL   VersionIHL
		expected uint8
	}{
		{
			name:     "Get IHL",
			verIHL:   VersionIHL{Value: 78},
			expected: 14,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := test.verIHL.IHL()

			if val != test.expected {
				t.Errorf("IHL not expected %d", val)
			}
		})
	}
}

func Test_FlagsFrOffset_GetFlags(t *testing.T) {
	tests := []struct {
		name     string
		flfr     FlagsFrOffset
		expected uint16
	}{
		{
			name:     "Get Flags",
			flfr:     FlagsFrOffset{Value: 65535},
			expected: 7,
		},
		{
			name:     "Get empty Flags",
			flfr:     FlagsFrOffset{Value: 8191},
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := test.flfr.Flags()

			if val != test.expected {
				t.Errorf("Flags not expected %d", val)
			}
		})
	}
}

func Test_FlagsFrOffset_GetFragmentOffset(t *testing.T) {
	tests := []struct {
		name     string
		flfr     FlagsFrOffset
		expected uint16
	}{
		{
			name:     "Get FragmentOffset",
			flfr:     FlagsFrOffset{Value: 65535},
			expected: 8191,
		},
		{
			name:     "Get full FragmentOffset",
			flfr:     FlagsFrOffset{Value: 8191},
			expected: 8191,
		},
		{
			name:     "Get empty FragmentOffset",
			flfr:     FlagsFrOffset{Value: 57344},
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := test.flfr.FragmentOffset()

			if val != test.expected {
				t.Errorf("Fragment offset not expected %d", val)
			}
		})
	}
}

func Test_Packet_Marshal(t *testing.T) {
	ip1, _ := IPFromString("1.2.3.4")
	ip2, _ := IPFromString("1.2.3.4")

	p := New(ip1, ip2, []byte{0})
	data := p.Marshal()

	if len(data) != 21 {
		t.Error("wrong data length: ", data)
	}

	expected := []byte{69, 0, 0, 21, 0, 0, 0, 0, 64, 6, 255, 255, 1, 2, 3, 4, 1, 2, 3, 4, 0}

	for i, b := range data {
		if b != expected[i] {
			t.Error("marshaled not expected: ", data)
		}
	}
}

func Test_Packet_Marshal_WithOptions(t *testing.T) {
	ip1, _ := IPFromString("1.2.3.4")
	ip2, _ := IPFromString("1.2.3.4")

	p := New(ip1, ip2, []byte{0}).WithOptions(Option{Type: OptionType{0x00000001}})
	data := p.Marshal()

	if len(data) != 25 {
		t.Error("wrong data length: ", data)
	}

	expected := []byte{70, 0, 0, 25, 0, 0, 0, 0, 64, 6, 255, 255, 1, 2, 3, 4, 1, 2, 3, 4, 1, 1, 1, 0, 0}

	for i, b := range data {
		if b != expected[i] {
			t.Error("marshaled not expected: ", data)
		}
	}
}

func Test_Packet_Unmarshal(t *testing.T) {
	data := []byte{69, 0, 0, 21, 0, 0, 0, 0, 64, 6, 255, 255, 1, 2, 3, 4, 1, 2, 3, 4, 0}

	templ := "wrong unmarshaling %v"

	p := &Packet{}
	p.Unmarshal(data)

	if p.VerIHL.Version() != 4 {
		t.Error(fmt.Errorf(templ, p.VerIHL.Version()))
	}

	if p.VerIHL.IHL() != 5 {
		t.Error(fmt.Errorf(templ, p.VerIHL.IHL()))
	}

	if p.TOS != 0 {
		t.Error(fmt.Errorf(templ, p.TOS))
	}

	if p.Length != 21 {
		t.Error(fmt.Errorf(templ, p.Length))
	}

	if p.ID != 0 {
		t.Error(fmt.Errorf(templ, p.ID))
	}

	if p.FlFrOff.Flags() != 0 {
		t.Error(fmt.Errorf(templ, p.FlFrOff.Flags()))
	}

	if p.FlFrOff.FragmentOffset() != 0 {
		t.Error(fmt.Errorf(templ, p.FlFrOff.FragmentOffset()))
	}

	if p.TTL != 64 {
		t.Error(fmt.Errorf(templ, p.TTL))
	}

	if p.Protocol != 6 {
		t.Error(fmt.Errorf(templ, p.Protocol))
	}

	if p.Checksum != 0xFFFF {
		t.Error(fmt.Errorf(templ, p.Checksum))
	}

	if p.Src.String() != "1.2.3.4" {
		t.Error(fmt.Errorf(templ, p.Src.String()))
	}

	if p.Dst.String() != "1.2.3.4" {
		t.Error(fmt.Errorf(templ, p.Dst.String()))
	}
}

func Test_Packet_Unmarshal_WithOptions(t *testing.T) {
	data := []byte{71, 0, 0, 33, 0, 0, 0, 0, 64, 6, 255, 255, 1, 2, 3, 4, 1, 2, 3, 4, 134, 3, 14, 166, 3, 15, 1, 0, 0, 1, 2, 3, 4}

	templ := "wrong unmarshaling %v"

	p := &Packet{}
	p.Unmarshal(data)

	if p.VerIHL.Version() != 4 {
		t.Error(fmt.Errorf(templ, p.VerIHL.Version()))
	}

	if p.VerIHL.IHL() != 7 {
		t.Error(fmt.Errorf(templ, p.VerIHL.IHL()))
	}

	if p.TOS != 0 {
		t.Error(fmt.Errorf(templ, p.TOS))
	}

	if p.Length != 33 {
		t.Error(fmt.Errorf(templ, p.Length))
	}

	if p.ID != 0 {
		t.Error(fmt.Errorf(templ, p.ID))
	}

	if p.FlFrOff.Flags() != 0 {
		t.Error(fmt.Errorf(templ, p.FlFrOff.Flags()))
	}

	if p.FlFrOff.FragmentOffset() != 0 {
		t.Error(fmt.Errorf(templ, p.FlFrOff.FragmentOffset()))
	}

	if p.TTL != 64 {
		t.Error(fmt.Errorf(templ, p.TTL))
	}

	if p.Protocol != 6 {
		t.Error(fmt.Errorf(templ, p.Protocol))
	}

	if p.Checksum != 0xFFFF {
		t.Error(fmt.Errorf(templ, p.Checksum))
	}

	if p.Src.String() != "1.2.3.4" {
		t.Error(fmt.Errorf(templ, p.Src.String()))
	}

	if p.Dst.String() != "1.2.3.4" {
		t.Error(fmt.Errorf(templ, p.Dst.String()))
	}

	options := []Option{{Type: OptionType{134}, Length: 3}, {Type: OptionType{166}, Length: 3}, {Type: OptionType{1}}, {Type: OptionType{0}}}

	for i, opt := range options {
		if p.Options[i].Type != opt.Type {
			t.Error("failed to unmarshal options")
		}

		if p.Options[i].Length != opt.Length {
			t.Error("failed to unmarshal length of option")
		}
	}

	payload := []byte{0, 1, 2, 3, 4}

	for i, b := range payload {
		if p.Data[i] != b {
			t.Error("wrong payload unmarshal")
		}
	}

	if p.Length != uint16(len(data)) {
		t.Error("wrong length field")
	}
}
