package ipv4

import "testing"

func Test_OptionType_Copied(t *testing.T) {
	tests := []struct {
		name     string
		opType   OptionType
		expected uint8
	}{
		{
			name:     "Get true copied",
			opType:   OptionType{Value: 128},
			expected: 1,
		},
		{
			name:     "Get false copied",
			opType:   OptionType{Value: 0b01111111},
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := test.opType.Copied()

			if val != test.expected {
				t.Errorf("Copied not expected %d", val)
			}
		})
	}
}

func Test_OptionType_Class(t *testing.T) {
	tests := []struct {
		name     string
		opType   OptionType
		expected uint8
	}{
		{
			name:     "Get control class",
			opType:   OptionType{Value: 145},
			expected: 0,
		},
		{
			name:     "Get debug class",
			opType:   OptionType{Value: 209},
			expected: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := test.opType.Class()

			if val != test.expected {
				t.Errorf("Class not expected %d", val)
			}
		})
	}
}

func Test_OptionType_Number(t *testing.T) {
	tests := []struct {
		name     string
		opType   OptionType
		expected uint8
	}{
		{
			name:     "Get End of Option List",
			opType:   OptionType{Value: 224},
			expected: 0,
		},
		{
			name:     "Get No Operation",
			opType:   OptionType{Value: 225},
			expected: 1,
		},
		{
			name:     "Get Record Route",
			opType:   OptionType{Value: 231},
			expected: 7,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := test.opType.Number()

			if val != test.expected {
				t.Errorf("Number not expected %d", val)
			}
		})
	}
}

func Test_Option_Marshal(t *testing.T) {
	tests := []struct {
		name     string
		option   Option
		expected []byte
	}{
		{
			name:     "Get End of Option List",
			option:   Option{},
			expected: []byte{0x00},
		},
		{
			name:     "Get No Operation",
			option:   Option{Type: OptionType{Value: 225}},
			expected: []byte{225},
		},
		{
			name:     "Get Record Route",
			option:   Option{Type: OptionType{Value: 231}, Length: 3, Value: []byte{0xFF}},
			expected: []byte{231, 3, 0xFF},
		},
		{
			name:     "Value with wrong length",
			option:   Option{Type: OptionType{Value: 231}, Length: 3, Value: []byte{0xFF, 0xFE, 0xFD}},
			expected: []byte{231, 3, 0xFF},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := test.option.Marshal()

			if len(val) != len(test.expected) {
				t.Error("Wrong length")
			}

			for i, b := range test.expected {
				if b != val[i] {
					t.Errorf("Marshaled %d not equeal expected %d", val[i], b)
				}
			}
		})
	}
}

func Test_Option_Unmarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected Option
	}{
		{
			name:     "Get End of Option List",
			input:    []byte{0x00},
			expected: Option{},
		},
		{
			name:     "Get No Operation",
			input:    []byte{225},
			expected: Option{Type: OptionType{Value: 225}},
		},
		{
			name:     "Get Record Route",
			input:    []byte{231, 3, 0xFF},
			expected: Option{Type: OptionType{Value: 231}, Length: 3, Value: []byte{0xFF}},
		},
		{
			name:     "Value with wrong length",
			expected: Option{Type: OptionType{Value: 231}, Length: 3, Value: []byte{0xFF}},
			input:    []byte{231, 3, 0xFF, 0xFE, 0xFD},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := Option{}
			p.Unmarshal(test.input)

			if test.expected.Type != p.Type {
				t.Errorf("Type not equal %d - %d", test.expected.Type, p.Type)
			}

			if test.expected.Length != p.Length {
				t.Errorf("Length not equal %d - %d", test.expected.Length, p.Length)
			}

			for i, b := range test.expected.Value {
				if b != p.Value[i] {
					t.Errorf("Marshaled %d not equeal expected %d", p.Value[i], b)
				}
			}
		})
	}
}
