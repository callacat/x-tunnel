package app

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// ======================== DNS 嗅探（方案 §2.2） ========================
//
// x-tunnel 的 DNS 查询经 hev tun2socks 转发为 SOCKS5-based UDP 报文进入
// sidecar（UDPAssociation）。本包在 UDP 中继**响应侧**旁路解析 DNS 报文：
// 从响应提取 QNAME + A/AAAA 答案，把「IP→域名」写入 routeRT 映射（TTL 10min，
// 见 route.go dnsMap）。映射供 SOCKS5/HTTP 的 IP 字面量目标反查域名，使
// geosite/domain 规则生效（对齐 warp-go dnsInterceptor）。
//
// 报文格式按 RFC 1035 手写最小解析（不引入 x/net 依赖，方案宁简勿繁）：
// 只处理 NOERROR、包含 A 或 AAAA 答案的响应。

const (
	dnsTypeA     = 1
	dnsTypeAAAA  = 28
	dnsClassINet = 1

	// DNS 报头 12 字节；QR 在 flags 第 15 位。
	dnsHeaderLen = 12
	dnsFlagQR    = 0x8000
	// RCODE 低 4 位；0 = NoError。
	dnsRCodeMask = 0x000f
)

// sniffDNSAnswers 从 DNS 响应报文中提取 (qname, ips)——问题 QNAME + 答案里的 A/AAAA IP。
// 返回的 ips 供 routeRT.remember 写入 IP→域名映射。不合规返回 ("" , nil)。
func sniffDNSAnswers(payload []byte) (string, []netip.Addr) {
	if len(payload) < dnsHeaderLen {
		return "", nil
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&dnsFlagQR == 0 { // 不是响应
		return "", nil
	}
	if flags&dnsRCodeMask != 0 { // 仅 NoError
		return "", nil
	}
	off := dnsHeaderLen
	// 跳过问题段（通常 1 个）。
	qdcount := int(binary.BigEndian.Uint16(payload[4:6]))
	var qname string
	for i := 0; i < qdcount; i++ {
		name, consumed, ok := parseDNSName(payload, off)
		if !ok {
			return "", nil
		}
		off += consumed
		if off+4 > len(payload) {
			return "", nil
		}
		if i == 0 {
			qname = strings.TrimSuffix(name, ".")
		}
		off += 4 // QTYPE + QCLASS
	}
	ancount := int(binary.BigEndian.Uint16(payload[6:8]))
	var ips []netip.Addr
	for i := 0; i < ancount; i++ {
		// 答案 NAME 可能压缩（指针），跳过它（2 字节压缩指针或域名）。
		_, consumed, ok := parseDNSName(payload, off)
		if !ok {
			break
		}
		off += consumed
		if off+10 > len(payload) {
			break
		}
		rtype := binary.BigEndian.Uint16(payload[off : off+2])
		_ = binary.BigEndian.Uint16(payload[off+2 : off+4]) // class
		_ = binary.BigEndian.Uint32(payload[off+4 : off+8]) // ttl
		rdlen := int(binary.BigEndian.Uint16(payload[off+8 : off+10]))
		off += 10
		if off+rdlen > len(payload) {
			break
		}
		switch rtype {
		case dnsTypeA:
			if rdlen == 4 {
				if ip, ok := netip.AddrFromSlice(payload[off : off+4]); ok {
					ips = append(ips, ip)
				}
			}
		case dnsTypeAAAA:
			if rdlen == 16 {
				if ip, ok := netip.AddrFromSlice(payload[off : off+16]); ok {
					ips = append(ips, ip)
				}
			}
		}
		off += rdlen
	}
	return qname, ips
}

// parseDNSName 从 offset 起解析 DNS 域名（支持 0xC0 压缩指针），返回名字与
// 消耗的字节数（包含压缩指针的 2 字节，指针不向前推进）。名字以 '.' 分隔。
func parseDNSName(payload []byte, offset int) (string, int, bool) {
	if offset >= len(payload) {
		return "", 0, false
	}
	var labels []string
	pos := offset
	consumed := 0 // 仅用于非压缩路径的字节消耗
	ptr := false
	hops := 0
	for hops < 128 { // 防压缩指针死循环
		if pos >= len(payload) {
			return "", 0, false
		}
		l := int(payload[pos])
		switch {
		case l&0xC0 == 0xC0: // 压缩指针
			if pos+1 >= len(payload) {
				return "", 0, false
			}
			target := int(l&0x3F)<<8 | int(payload[pos+1])
			if !ptr {
				consumed = pos + 2 - offset
				ptr = true
			}
			pos = target
			hops++
			continue
		case l&0xC0 != 0:
			return "", 0, false
		case l == 0: // 终止
			if !ptr {
				consumed = pos + 1 - offset
			}
			if len(labels) == 0 {
				return ".", consumed, true // 根域名
			}
			return strings.Join(labels, "."), consumed, true
		default:
			pos++
			if pos+l > len(payload) {
				return "", 0, false
			}
			labels = append(labels, string(payload[pos:pos+l]))
			pos += l
		}
	}
	return "", 0, false
}
