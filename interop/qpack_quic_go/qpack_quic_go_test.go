package qpack_quic_go

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/quic-go/qpack"
)

type field struct {
	name  string
	value string
}

type fixture struct {
	name     string
	fields   []field
	blockHex string
}

var fixtures = []fixture{
	{
		name: "request_static_and_literal",
		fields: []field{
			{name: ":method", value: "GET"},
			{name: ":scheme", value: "https"},
			{name: ":path", value: "/search"},
			{name: ":authority", value: "example.com"},
			{name: "user-agent", value: "null3-test"},
		},
		blockHex: "0000d1d7518561051d849f50882f91d35d055c87a75f5087aada2865649509",
	},
	{
		name: "response_static_and_literal",
		fields: []field{
			{name: ":status", value: "200"},
			{name: "content-type", value: "text/plain"},
			{name: "cache-control", value: "no-cache"},
			{name: "x-trace-id", value: "abcdef"},
		},
		blockHex: "0000d9f5e72f00f2b26c190ab1a4851c6490b2ff",
	},
	{
		name: "literal_without_name_reference",
		fields: []field{
			{name: "x-custom-key", value: "x-custom-value"},
		},
		blockHex: "00002f02f2b12d424f4add4beb8af2b12d424f4addc745a5",
	},
}

func TestQuicGoQpackFixtures(t *testing.T) {
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			expected, err := hex.DecodeString(tc.blockHex)
			if err != nil {
				t.Fatalf("decode fixture hex: %v", err)
			}

			block := encode(t, tc.fields)
			if !bytes.Equal(block, expected) {
				t.Fatalf("encoded block = %s, want %s", hex.EncodeToString(block), tc.blockHex)
			}

			got := decode(t, expected)
			if len(got) != len(tc.fields) {
				t.Fatalf("decoded %d fields, want %d", len(got), len(tc.fields))
			}
			for i := range tc.fields {
				if got[i] != tc.fields[i] {
					t.Fatalf("field %d = %#v, want %#v", i, got[i], tc.fields[i])
				}
			}
		})
	}
}

func encode(t *testing.T, fields []field) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for _, f := range fields {
		if err := enc.WriteField(qpack.HeaderField{Name: f.name, Value: f.value}); err != nil {
			t.Fatalf("encode field %#v: %v", f, err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close encoder: %v", err)
	}
	return buf.Bytes()
}

func decode(t *testing.T, block []byte) []field {
	t.Helper()
	next := qpack.NewDecoder().Decode(block)
	var out []field
	for {
		hf, err := next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("decode block %x: %v", block, err)
		}
		out = append(out, field{name: hf.Name, value: hf.Value})
	}
}
