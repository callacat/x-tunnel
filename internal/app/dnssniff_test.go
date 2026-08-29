package app

import (
	"net/netip"
	"testing"
)

// 手写最小 DNS 报文构造（测试用），覆盖 A/AAAA 响应解析与指针压缩。

func buildDNSPacket(flags uint16, qname string, answers []dnsTestAnswer) []byte {
	var b []byte
	// Header: ID=0x1234, flags, qdcount, ancount, nscount=0, arcount=0
	b = append(b, 0x12, 0x34)
	b = append(b, byte(flags>>8), byte(flags))
	b = append(b, 0x00, 0x01) // qdcount=1
	b = append(b, 0x00, byte(len(answers)))
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	// Question: qname encoded + QTYPE=A + QCLASS=IN
	b = appendEncodedName(b, qname)
	b = append(b, 0x00, dnsTypeA, 0x00, dnsClassINet)
	for _, a := range answers {
		// Answer NAME 用压缩指针指向 question 起始（偏移 12）。
		b = append(b, 0xC0, 0x0C)
		b = append(b, byte(a.rtype>>8), byte(a.rtype))
		b = append(b, 0x00, dnsClassINet)
		b = append(b, 0x00, 0x00, 0x00, 0x3C) // ttl=60
		b = append(b, byte(len(a.rdata)>>8), byte(len(a.rdata)))
		b = append(b, a.rdata...)
	}
	return b
}

type dnsTestAnswer struct {
	rtype uint16
	rdata []byte
}

func appendEncodedName(b []byte, name string) []byte {
	if name == "" {
		return append(b, 0)
	}
	parts := splitNameLabels(name)
	for _, p := range parts {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return append(b, 0)
}

func splitNameLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestSniffDNSAnswersA(t *testing.T) {
	payload := buildDNSPacket(dnsFlagQR, "example.com", []dnsTestAnswer{
		{rtype: dnsTypeA, rdata: []byte{93, 184, 216, 34}},
	})
	qname, ips := sniffDNSAnswers(payload)
	if qname != "example.com" {
		t.Fatalf("qname = %q, want example.com", qname)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("ips = %v", ips)
	}
}

func TestSniffDNSAnswersAAAA(t *testing.T) {
	payload := buildDNSPacket(dnsFlagQR, "example.com", []dnsTestAnswer{
		{rtype: dnsTypeAAAA, rdata: []byte{0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46}},
	})
	qname, ips := sniffDNSAnswers(payload)
	if qname != "example.com" {
		t.Fatalf("qname = %q", qname)
	}
	if len(ips) != 1 || ips[0].String() != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Fatalf("ips = %v", ips)
	}
}

func TestSniffDNSAnswersIgnoresQuery(t *testing.T) {
	payload := buildDNSPacket(0x0000, "example.com", nil)
	qname, ips := sniffDNSAnswers(payload)
	if qname != "" || ips != nil {
		t.Fatalf("query should be ignored, got (%q, %v)", qname, ips)
	}
}

func TestSniffDNSAnswersIgnoresErrorRCode(t *testing.T) {
	payload := buildDNSPacket(dnsFlagQR|0x0003, "example.com", []dnsTestAnswer{
		{rtype: dnsTypeA, rdata: []byte{93, 184, 216, 34}},
	})
	qname, ips := sniffDNSAnswers(payload)
	if qname != "" || ips != nil {
		t.Fatalf("error rcode should be ignored, got (%q, %v)", qname, ips)
	}
}

func TestParseDNSNamePlain(t *testing.T) {
	payload := appendEncodedName(nil, "www.example.com")
	name, consumed, ok := parseDNSName(payload, 0)
	if !ok || name != "www.example.com" {
		t.Fatalf("got (%q, %d, %v)", name, consumed, ok)
	}
	if consumed != len(payload) {
		t.Fatalf("consumed = %d, want %d", consumed, len(payload))
	}
}

func TestParseDNSNameCompressedPointer(t *testing.T) {
	// 偏移 0 处是压缩指针指向偏移 2 的 "ex.com" 标签。
	var b []byte
	b = append(b, 0xC0, 0x02) // 指针 → offset 2
	b = append(b, 0x02, 'e', 'x', 0x03, 'c', 'o', 'm', 0x00)
	name, consumed, ok := parseDNSName(b, 0)
	if !ok || name != "ex.com" {
		t.Fatalf("got (%q, %d, %v)", name, consumed, ok)
	}
	if consumed != 2 { // 指针占 2 字节
		t.Fatalf("consumed = %d, want 2", consumed)
	}
}
