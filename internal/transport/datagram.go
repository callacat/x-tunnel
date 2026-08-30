package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	AddrTypeIPv4   byte = 0x01
	AddrTypeDomain byte = 0x03
	AddrTypeIPv6   byte = 0x04

	MaxDatagramSize = 1400
	DefaultMTU      = 1200
)

var (
	ErrInvalidDatagram      = errors.New("transport: invalid datagram format")
	ErrDatagramTooLarge     = errors.New("transport: datagram exceeds maximum supported size")
	ErrUnsupportedAddrType  = errors.New("transport: unsupported address type")
	ErrIncompleteFragments  = errors.New("transport: incomplete datagram fragments")
	ErrReassemblerQueueFull = errors.New("transport: reassembly queue is full")
)

// DatagramFrame represents an RFC 9221 datagram frame for UDP proxying.
type DatagramFrame struct {
	AssocID    uint16
	PktID      uint16
	FragTotal  uint8
	FragID     uint8
	PayloadLen uint16
	AddrType   byte
	TargetAddr string
	TargetPort uint16
	Payload    []byte
}

// EncodeDatagram encodes a DatagramFrame into binary wire format.
func EncodeDatagram(frame DatagramFrame) ([]byte, error) {
	if int(frame.PayloadLen) != len(frame.Payload) {
		frame.PayloadLen = uint16(len(frame.Payload))
	}

	var addrBytes []byte
	switch frame.AddrType {
	case AddrTypeIPv4:
		ip := net.ParseIP(frame.TargetAddr).To4()
		if ip == nil {
			return nil, fmt.Errorf("%w: invalid IPv4 address %q", ErrInvalidDatagram, frame.TargetAddr)
		}
		addrBytes = ip
	case AddrTypeDomain:
		if len(frame.TargetAddr) > 255 {
			return nil, fmt.Errorf("%w: domain name too long", ErrInvalidDatagram)
		}
		addrBytes = make([]byte, 1+len(frame.TargetAddr))
		addrBytes[0] = byte(len(frame.TargetAddr))
		copy(addrBytes[1:], frame.TargetAddr)
	case AddrTypeIPv6:
		ip := net.ParseIP(frame.TargetAddr).To16()
		if ip == nil {
			return nil, fmt.Errorf("%w: invalid IPv6 address %q", ErrInvalidDatagram, frame.TargetAddr)
		}
		addrBytes = ip
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedAddrType, frame.AddrType)
	}

	// Header: AssocID(2) + PktID(2) + FragTotal(1) + FragID(1) + PayloadLen(2) + AddrType(1) + Addr(var) + Port(2) + Payload(var)
	totalLen := 8 + 1 + len(addrBytes) + 2 + len(frame.Payload)
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint16(buf[0:2], frame.AssocID)
	binary.BigEndian.PutUint16(buf[2:4], frame.PktID)
	buf[4] = frame.FragTotal
	buf[5] = frame.FragID
	binary.BigEndian.PutUint16(buf[6:8], frame.PayloadLen)
	buf[8] = frame.AddrType

	offset := 9
	copy(buf[offset:], addrBytes)
	offset += len(addrBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], frame.TargetPort)
	offset += 2

	copy(buf[offset:], frame.Payload)
	return buf, nil
}

// DecodeDatagram decodes binary bytes into a DatagramFrame.
func DecodeDatagram(b []byte) (DatagramFrame, error) {
	if len(b) < 11 { // Minimal: 8 hdr + 1 addrType + (at least 0 addr) + 2 port
		return DatagramFrame{}, ErrInvalidDatagram
	}

	frame := DatagramFrame{
		AssocID:    binary.BigEndian.Uint16(b[0:2]),
		PktID:      binary.BigEndian.Uint16(b[2:4]),
		FragTotal:  b[4],
		FragID:     b[5],
		PayloadLen: binary.BigEndian.Uint16(b[6:8]),
		AddrType:   b[8],
	}

	if frame.FragTotal == 0 {
		frame.FragTotal = 1
	}

	offset := 9
	switch frame.AddrType {
	case AddrTypeIPv4:
		if len(b) < offset+4+2 {
			return DatagramFrame{}, ErrInvalidDatagram
		}
		frame.TargetAddr = net.IP(b[offset : offset+4]).String()
		offset += 4
	case AddrTypeDomain:
		if len(b) < offset+1 {
			return DatagramFrame{}, ErrInvalidDatagram
		}
		domainLen := int(b[offset])
		offset++
		if len(b) < offset+domainLen+2 {
			return DatagramFrame{}, ErrInvalidDatagram
		}
		frame.TargetAddr = string(b[offset : offset+domainLen])
		offset += domainLen
	case AddrTypeIPv6:
		if len(b) < offset+16+2 {
			return DatagramFrame{}, ErrInvalidDatagram
		}
		frame.TargetAddr = net.IP(b[offset : offset+16]).String()
		offset += 16
	default:
		return DatagramFrame{}, fmt.Errorf("%w: 0x%02x", ErrUnsupportedAddrType, frame.AddrType)
	}

	frame.TargetPort = binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2

	if len(b) < offset+int(frame.PayloadLen) {
		return DatagramFrame{}, ErrInvalidDatagram
	}

	frame.Payload = make([]byte, frame.PayloadLen)
	copy(frame.Payload, b[offset:offset+int(frame.PayloadLen)])

	return frame, nil
}

// FragmentDatagram slices a DatagramFrame into multiple smaller DatagramFrames if payload exceeds maxPayloadSize.
func FragmentDatagram(frame DatagramFrame, maxPayloadSize int) []DatagramFrame {
	if maxPayloadSize <= 0 || len(frame.Payload) <= maxPayloadSize {
		frame.FragTotal = 1
		frame.FragID = 0
		frame.PayloadLen = uint16(len(frame.Payload))
		return []DatagramFrame{frame}
	}

	totalFrags := (len(frame.Payload) + maxPayloadSize - 1) / maxPayloadSize
	if totalFrags > 255 {
		totalFrags = 255
	}

	frames := make([]DatagramFrame, 0, totalFrags)
	for i := 0; i < totalFrags; i++ {
		start := i * maxPayloadSize
		end := start + maxPayloadSize
		if end > len(frame.Payload) {
			end = len(frame.Payload)
		}
		f := frame
		f.FragTotal = uint8(totalFrags)
		f.FragID = uint8(i)
		f.Payload = frame.Payload[start:end]
		f.PayloadLen = uint16(len(f.Payload))
		frames = append(frames, f)
	}
	return frames
}

type fragmentEntry struct {
	fragments map[uint8][]byte
	total     uint8
	frame     DatagramFrame
	createdAt time.Time
}

// DatagramReassembler reassembles fragmented datagram frames with expiration and bounded capacity.
type DatagramReassembler struct {
	mu        sync.Mutex
	entries   map[uint32]*fragmentEntry
	ttl       time.Duration
	maxQueued int
}

// NewDatagramReassembler creates a new DatagramReassembler with a specified TTL and max capacity.
func NewDatagramReassembler(ttl time.Duration, maxQueued int) *DatagramReassembler {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	if maxQueued <= 0 {
		maxQueued = 1024
	}
	return &DatagramReassembler{
		entries:   make(map[uint32]*fragmentEntry),
		ttl:       ttl,
		maxQueued: maxQueued,
	}
}

// Add processes a DatagramFrame. If the frame is complete (single fragment or final missing fragment arrived),
// it returns the fully assembled DatagramFrame and true. Otherwise it returns false.
func (r *DatagramReassembler) Add(f DatagramFrame) (DatagramFrame, bool, error) {
	if f.FragTotal <= 1 {
		return f, true, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.cleanupExpiredLocked()

	key := (uint32(f.AssocID) << 16) | uint32(f.PktID)
	entry, exists := r.entries[key]
	if !exists {
		if len(r.entries) >= r.maxQueued {
			return DatagramFrame{}, false, ErrReassemblerQueueFull
		}
		entry = &fragmentEntry{
			fragments: make(map[uint8][]byte),
			total:     f.FragTotal,
			frame:     f,
			createdAt: time.Now(),
		}
		r.entries[key] = entry
	}

	entry.fragments[f.FragID] = f.Payload

	if len(entry.fragments) == int(entry.total) {
		// All fragments arrived, stitch payload
		var totalLen int
		for i := uint8(0); i < entry.total; i++ {
			totalLen += len(entry.fragments[i])
		}
		combined := make([]byte, 0, totalLen)
		for i := uint8(0); i < entry.total; i++ {
			combined = append(combined, entry.fragments[i]...)
		}
		delete(r.entries, key)

		result := entry.frame
		result.FragTotal = 1
		result.FragID = 0
		result.Payload = combined
		result.PayloadLen = uint16(len(combined))
		return result, true, nil
	}

	return DatagramFrame{}, false, nil
}

func (r *DatagramReassembler) cleanupExpiredLocked() {
	now := time.Now()
	for k, v := range r.entries {
		if now.Sub(v.createdAt) > r.ttl {
			delete(r.entries, k)
		}
	}
}
