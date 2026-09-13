package app

import (
	"encoding/binary"
	"strings"
)

// ======================== TLS ClientHello SNI 嗅探（任务方案 round47：裸 IP 进隧道） ========================
//
// round47 修复「裸 IP 进隧道」：Android 端系统 DNS 走 DoT(:853) 加密解析，
// sidecar 的 UDP:53 嗅探拿不到 IP→域名映射，SOCKS5 CONNECT 目标全是裸 IP
// 字面量，服务端 MIhomo 的域名分流规则（geosite/domain）全部失效。
// 对策：对判定走代理的 443 连接嗅探 TLS ClientHello 的 SNI，把 target 改写为
// domain:port 发给服务器——服务器在境外视角解析（无污染）且域名规则恢复。
//
// 报文格式按 RFC 8446 §4.1.2 / §5.1 与 RFC 6066 §3 手写最小解析（零新依赖，
// 对齐同包 dnssniff.go 的风格）：只提取 server_name 扩展里的 host_name。
// 所有非预期情形（非 handshake、非 ClientHello、截断、SNI 缺失/非法）一律
// 安静返回 false（不 panic、不报错），由调用方决定是否改写。

const (
	tlsRecordHandshake      = 0x16   // TLS record type：handshake
	tlsHandshakeClientHello = 0x01   // handshake type：ClientHello
	tlsExtServerName        = 0x0000 // ExtensionType：server_name（RFC 6066 §3）
	tlsSNIHostName          = 0x00   // NameType：host_name
)

// sniffSNI 从 TLS 记录层首包提取 ClientHello 的 SNI 域名。
// 返回 ok=false 的情形：非 TLS 记录（0x16 handshake 之外）、非 ClientHello、
// 版本前置不对、SNI 扩展缺失、SNI 非完整 host 名、截断等——一律安静 false。
func sniffSNI(payload []byte) (string, bool) {
	// TLS record header：type(1) + version(2) + length(2)，共 5 字节。
	if len(payload) < 5 {
		return "", false
	}
	if payload[0] != tlsRecordHandshake { // 非 handshake 记录
		return "", false
	}
	if payload[1] != 0x03 { // 版本首字节必须 0x03（TLS 1.0 及之后）
		return "", false
	}
	// handshake header：type(1) + length(3)，共 4 字节。
	if len(payload) < 9 {
		return "", false
	}
	if payload[5] != tlsHandshakeClientHello { // 非 ClientHello
		return "", false
	}
	hsLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	// payload 必须 ≥ 完整 ClientHello 才解析（允许略长：首包可能只含 ClientHello，
	// 不要求解析到 record 结尾）。
	if len(payload) < 5+4+hsLen {
		return "", false
	}
	return parseClientHelloSNI(payload[9 : 9+hsLen])
}

// parseClientHelloSNI 在 ClientHello body 内定位 server_name 扩展并提取 host_name。
// body 不含 handshake 头（从 legacy_version 起，见 RFC 8446 §4.1.2）：
// legacy_version(2) + random(32) + legacy_session_id(1+N) + cipher_suites(2+N) +
// compression_methods(1+N) + extensions(2+N)。
func parseClientHelloSNI(body []byte) (string, bool) {
	// legacy_version(2) + random(32)
	off := 2 + 32
	if off > len(body) {
		return "", false
	}
	// legacy_session_id(1+N)
	if off+1 > len(body) {
		return "", false
	}
	sidLen := int(body[off])
	off += 1 + sidLen
	if off > len(body) {
		return "", false
	}
	// cipher_suites(2+N)
	if off+2 > len(body) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + csLen
	if off > len(body) {
		return "", false
	}
	// compression_methods(1+N)
	if off+1 > len(body) {
		return "", false
	}
	cmLen := int(body[off])
	off += 1 + cmLen
	if off > len(body) {
		return "", false
	}
	// extensions(2+N)：总长度在 body 内即合法，逐项遍历。
	if off+2 > len(body) {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extTotal > len(body) {
		return "", false
	}
	extEnd := off + extTotal
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd { // 该项超出 extensions 块 → 截断
			return "", false
		}
		if extType == tlsExtServerName {
			return parseServerNameExt(body[off : off+extLen])
		}
		off += extLen
	}
	return "", false
}

// parseServerNameExt 解析 server_name 扩展数据：server_name_list(2+N)，
// 每项 NameType(1) + Name length(2) + Name（RFC 6066 §3）。
func parseServerNameExt(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+listLen {
		return "", false
	}
	list := data[2 : 2+listLen]
	off := 0
	for off < len(list) {
		if off+3 > len(list) {
			return "", false
		}
		nameType := list[off]
		nameLen := int(binary.BigEndian.Uint16(list[off+1 : off+3]))
		off += 3
		if off+nameLen > len(list) {
			return "", false
		}
		if nameType == tlsSNIHostName {
			host := string(list[off : off+nameLen])
			if isValidSNIHostname(host) {
				return host, true
			}
			return "", false
		}
		off += nameLen // 跳过非 host_name 项
	}
	return "", false
}

// isValidSNIHostname 保守校验 SNI 是否为完整主机名（对齐 netaddr.ValidHostname 语义）：
// 只允许 [a-zA-Z0-9.-]（'.' 为分隔符）；总长 1-253；label 非空且 ≤63；
// label 不以 '-' 起止；末尾不得有点。纯数字点分形式视为 IP 字面量——客户端本
// 就直连 IP，无改写意义——一律 false。
func isValidSNIHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if host[len(host)-1] == '.' {
		return false
	}
	hasLetter := false
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
				hasLetter = true
			case c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return hasLetter
}
