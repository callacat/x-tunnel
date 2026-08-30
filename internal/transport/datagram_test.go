package transport

import (
	"bytes"
	"testing"
	"time"
)

func TestDatagramEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		frame DatagramFrame
	}{
		{
			name: "IPv4 single fragment",
			frame: DatagramFrame{
				AssocID:    1001,
				PktID:      42,
				FragTotal:  1,
				FragID:     0,
				AddrType:   AddrTypeIPv4,
				TargetAddr: "1.2.3.4",
				TargetPort: 8080,
				Payload:    []byte("hello datagram ipv4"),
			},
		},
		{
			name: "Domain single fragment",
			frame: DatagramFrame{
				AssocID:    1002,
				PktID:      43,
				FragTotal:  1,
				FragID:     0,
				AddrType:   AddrTypeDomain,
				TargetAddr: "example.com",
				TargetPort: 443,
				Payload:    []byte("hello datagram domain"),
			},
		},
		{
			name: "IPv6 single fragment",
			frame: DatagramFrame{
				AssocID:    1003,
				PktID:      44,
				FragTotal:  1,
				FragID:     0,
				AddrType:   AddrTypeIPv6,
				TargetAddr: "2001:db8::1",
				TargetPort: 53,
				Payload:    []byte("hello datagram ipv6"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeDatagram(tc.frame)
			if err != nil {
				t.Fatalf("EncodeDatagram: %v", err)
			}
			decoded, err := DecodeDatagram(encoded)
			if err != nil {
				t.Fatalf("DecodeDatagram: %v", err)
			}
			if decoded.AssocID != tc.frame.AssocID {
				t.Errorf("AssocID mismatch: %d != %d", decoded.AssocID, tc.frame.AssocID)
			}
			if decoded.PktID != tc.frame.PktID {
				t.Errorf("PktID mismatch: %d != %d", decoded.PktID, tc.frame.PktID)
			}
			if decoded.AddrType != tc.frame.AddrType {
				t.Errorf("AddrType mismatch: %d != %d", decoded.AddrType, tc.frame.AddrType)
			}
			if decoded.TargetAddr != tc.frame.TargetAddr {
				t.Errorf("TargetAddr mismatch: %s != %s", decoded.TargetAddr, tc.frame.TargetAddr)
			}
			if decoded.TargetPort != tc.frame.TargetPort {
				t.Errorf("TargetPort mismatch: %d != %d", decoded.TargetPort, tc.frame.TargetPort)
			}
			if !bytes.Equal(decoded.Payload, tc.frame.Payload) {
				t.Errorf("Payload mismatch: %q != %q", decoded.Payload, tc.frame.Payload)
			}
		})
	}
}

func TestDatagramFragmentationAndReassembly(t *testing.T) {
	origPayload := bytes.Repeat([]byte("abcdefghijklmnopqrstuvwxyz"), 100) // 2600 bytes
	origFrame := DatagramFrame{
		AssocID:    5001,
		PktID:      99,
		AddrType:   AddrTypeIPv4,
		TargetAddr: "8.8.8.8",
		TargetPort: 53,
		Payload:    origPayload,
	}

	frags := FragmentDatagram(origFrame, 500)
	if len(frags) != 6 { // ceil(2600 / 500) = 6
		t.Fatalf("expected 6 fragments, got %d", len(frags))
	}

	reassembler := NewDatagramReassembler(2*time.Second, 100)

	// Feed in reverse order
	var finalFrame DatagramFrame
	var complete bool
	for i := len(frags) - 1; i >= 0; i-- {
		res, ok, err := reassembler.Add(frags[i])
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		if ok {
			complete = true
			finalFrame = res
		}
	}

	if !complete {
		t.Fatal("expected reassembly to complete")
	}
	if !bytes.Equal(finalFrame.Payload, origPayload) {
		t.Fatalf("reassembled payload mismatch: length %d != %d", len(finalFrame.Payload), len(origPayload))
	}
	if finalFrame.AssocID != origFrame.AssocID || finalFrame.PktID != origFrame.PktID {
		t.Fatalf("metadata mismatch")
	}
}
