package app

import "testing"

// 手写最小 TLS ClientHello 构造（测试用），字节布局按 RFC 8446 §4.1.2：
// record header(5) + handshake header(4) + body，
// body = legacy_version(2) + random(32) + legacy_session_id(1+N) +
//        cipher_suites(2+N) + compression_methods(1+N) + extensions(2+N)。

// buildClientHello 构造最小合法 TLS ClientHello 记录。
// sni 为空或 withSNIExt=false 时不含 server_name 扩展。
func buildClientHello(sni string, withSNIExt bool) []byte {
	body := []byte{0x03, 0x03} // legacy_version = TLS 1.2
	for i := 0; i < 32; i++ {
		body = append(body, byte(i)) // random 32 字节（任意值）
	}
	body = append(body, 0x00)                   // legacy_session_id 长度 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites：长度 2 + TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression_methods：长度 1 + null
	if withSNIExt && sni != "" {
		name := appendSNIName(nil, sni)
		ext := []byte{0x00, 0x00} // server_name 扩展 type
		ext = append(ext, byte(len(name)>>8), byte(len(name)))
		ext = append(ext, name...)
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
		body = append(body, ext...)
	} else {
		body = append(body, 0x00, 0x00) // extensions 长度 0
	}
	// handshake header：type ClientHello(0x01) + 3 字节大端长度。
	hs := []byte{0x01}
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)
	// record header：type handshake(0x16) + version 0x0301 + 2 字节大端长度。
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	return append(rec, hs...)
}

// appendSNIName 构造 server_name 扩展的 ServerNameList：
// list 长度(2) + 每项 NameType(1) + Name 长度(2) + Name（RFC 6066 §3）。
func appendSNIName(b []byte, host string) []byte {
	itemLen := 1 + 2 + len(host) // type(1) + len(2) + host
	b = append(b, byte(itemLen>>8), byte(itemLen))
	b = append(b, tlsSNIHostName) // host_name
	b = append(b, byte(len(host)>>8), byte(len(host)))
	return append(b, host...)
}

// buildAppDataRecord 构造 record type=0x17（application_data）的报文，用于非 handshake 用例。
func buildAppDataRecord() []byte {
	body := []byte{0x01, 0x02, 0x03, 0x04}
	rec := []byte{0x17, 0x03, 0x03}
	rec = append(rec, byte(len(body)>>8), byte(len(body)))
	return append(rec, body...)
}

// buildServerHello 构造 handshake type=0x02（ServerHello）的报文，用于非 ClientHello 用例。
func buildServerHello() []byte {
	body := []byte{0x03, 0x03, 0x00, 0x01, 0x02, 0x03}
	hs := []byte{0x02} // ServerHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	return append(rec, hs...)
}

// buildExtLengthTruncated 构造扩展总长度字段超出实际数据的 ClientHello（内层截断用例）。
func buildExtLengthTruncated() []byte {
	body := []byte{0x03, 0x03}
	for i := 0; i < 32; i++ {
		body = append(body, 0)
	}
	body = append(body, 0x00)                   // legacy_session_id 长度 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression_methods
	body = append(body, 0x00, 0x08)             // extensions 声称 8 字节
	body = append(body, 0x00, 0x00, 0x00, 0x04) // 实际只有 4 字节扩展数据
	hs := []byte{0x01}
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	return append(rec, hs...)
}

// buildExtItemLengthTruncated 构造单个扩展项长度字段超出 extensions 块边界的 ClientHello。
func buildExtItemLengthTruncated() []byte {
	body := []byte{0x03, 0x03}
	for i := 0; i < 32; i++ {
		body = append(body, 0)
	}
	body = append(body, 0x00)                   // legacy_session_id 长度 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression_methods
	body = append(body, 0x00, 0x06)             // extensions 总长 6 字节
	body = append(body, 0x00, 0x00)             // server_name type
	body = append(body, 0x00, 0x04)             // 该项长度声称 4 字节
	body = append(body, 0x00, 0x00)             // 实际只有 2 字节数据
	hs := []byte{0x01}
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	return append(rec, hs...)
}

// truncate 返回前 n 字节，用于构造各阶段截断报文。
func truncate(b []byte, n int) []byte {
	if n >= len(b) {
		return b
	}
	return b[:n]
}

func TestSniffSNI(t *testing.T) {
	full := buildClientHello("www.example.com", true) // 完整合法报文，各阶段截断的基准
	tests := []struct {
		name    string
		payload []byte
		want    string
		wantOK  bool
	}{
		{"真实形态 ClientHello 含 SNI", buildClientHello("www.example.com", true), "www.example.com", true},
		{"国内域名", buildClientHello("cn.example.com", true), "cn.example.com", true},
		{"大小写保留", buildClientHello("WWW.Example.COM", true), "WWW.Example.COM", true},
		{"ClientHello 后带多余字节", append(buildClientHello("www.example.com", true), 0xde, 0xad), "www.example.com", true},
		{"无 SNI 扩展", buildClientHello("www.example.com", false), "", false},
		{"非 handshake record (0x17)", buildAppDataRecord(), "", false},
		{"非 ClientHello (ServerHello 0x02)", buildServerHello(), "", false},
		{"SNI 为纯 IP", buildClientHello("1.2.3.4", true), "", false},
		{"SNI 含非法字符", buildClientHello("bad_.example.com", true), "", false},
		{"空输入", []byte{}, "", false},
		{"nil", nil, "", false},
		{"截断 record header", truncate(full, 3), "", false},
		{"截断 handshake header", truncate(full, 7), "", false},
		{"截断 body 中途", truncate(full, 12), "", false},
		{"截断 extensions 中途", truncate(full, len(full)-8), "", false},
		{"截断 SNI host 中途", truncate(full, len(full)-3), "", false},
		{"扩展总长字段截断", buildExtLengthTruncated(), "", false},
		{"扩展项长度越界", buildExtItemLengthTruncated(), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sniffSNI(tt.payload)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("sniffSNI(%s) = (%q, %v), want (%q, %v)", tt.name, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
