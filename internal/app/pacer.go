package app

import (
	"io"
	"sync"
	"time"
)

// pacerWriter 是基于令牌桶的时间基发送限速器。
// 用于在客户端向 tunnel stream 写入时按指定速率限速并平滑突发流量。
type pacerWriter struct {
	w       io.Writer
	rate    float64 // bytes per second
	burst   float64 // 突发容量（字节，默认 64KB）
	tokens  float64 // 当前可用令牌数（字节）
	last    time.Time
	mu      sync.Mutex
	sleepFn func(d time.Duration) // 注入睡眠函数以便单测，默认 time.Sleep
}

// newPacerWriter 创建指定速率（字节/秒）与突发上限（字节）的 pacerWriter。
func newPacerWriter(w io.Writer, bytesPerSec float64, burstBytes float64) *pacerWriter {
	if burstBytes <= 0 {
		burstBytes = 64 * 1024
	}
	return &pacerWriter{
		w:       w,
		rate:    bytesPerSec,
		burst:   burstBytes,
		tokens:  burstBytes,
		last:    time.Now(),
		sleepFn: time.Sleep,
	}
}

// newPacerWriterMbps 创建指定速率（Mbps）的限速 writer。
// 1 Mbps = 1,000,000 bit/s = 125,000 B/s。
// 若 rateMbps <= 0，返回原始 writer，零开销。
func newPacerWriterMbps(w io.Writer, rateMbps float64) io.Writer {
	if rateMbps <= 0 {
		return w
	}
	bytesPerSec := rateMbps * 125000.0
	return newPacerWriter(w, bytesPerSec, 64*1024)
}

func (pw *pacerWriter) Write(p []byte) (int, error) {
	if pw == nil || pw.rate <= 0 {
		return pw.w.Write(p)
	}
	pw.mu.Lock()
	now := time.Now()
	if !pw.last.IsZero() {
		elapsed := now.Sub(pw.last).Seconds()
		pw.tokens += elapsed * pw.rate
		if pw.tokens > pw.burst {
			pw.tokens = pw.burst
		}
	}
	pw.last = now

	needed := float64(len(p))
	if pw.tokens < needed {
		deficit := needed - pw.tokens
		sleepSec := deficit / pw.rate
		pw.tokens = 0
		pw.last = pw.last.Add(time.Duration(sleepSec * float64(time.Second)))
		pw.mu.Unlock()

		if sleepSec > 0 {
			sleepDur := time.Duration(sleepSec * float64(time.Second))
			if pw.sleepFn != nil {
				pw.sleepFn(sleepDur)
			} else {
				time.Sleep(sleepDur)
			}
		}
	} else {
		pw.tokens -= needed
		pw.mu.Unlock()
	}

	return pw.w.Write(p)
}
