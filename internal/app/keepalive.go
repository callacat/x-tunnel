package app

import (
	"math/rand"
	"time"

	"github.com/xtaci/smux"
)

const defaultSmuxKeepAliveInterval = 10 * time.Second

// jitterKeepAliveWith 返回在 base 基础上增加 ±20% 均匀抖动后的时间间隔。
// 若 base <= 0 则直接返回 base。
// 否则返回 base * (0.8 + 0.4 * rand)，即 [0.8*base, 1.2*base)。
// 允许传入注入的 *rand.Rand 源以支持确定性单测。
func jitterKeepAliveWith(r *rand.Rand, base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	var f float64
	if r != nil {
		f = r.Float64()
	} else {
		f = rand.Float64()
	}
	multiplier := 0.8 + 0.4*f
	return time.Duration(float64(base) * multiplier)
}

// jitterKeepAlive 返回在 base 基础上增加 ±20% 均匀抖动后的时间间隔。
func jitterKeepAlive(base time.Duration) time.Duration {
	return jitterKeepAliveWith(nil, base)
}

// newSmuxConfig 构造 smux.Config。
// 防周期指纹：smux 默认固定 10s 发送一次 NOP keepalive，定期心跳会在审查系统产生明显的周期性时序特征。
// 这里在 smux.DefaultConfig() 基础上引入 ±20% (8s ~ 12s) 均匀抖动打乱周期性，其余配置完全保持一致。
func newSmuxConfig() *smux.Config {
	c := *smux.DefaultConfig()
	c.KeepAliveInterval = jitterKeepAlive(defaultSmuxKeepAliveInterval)
	return &c
}
