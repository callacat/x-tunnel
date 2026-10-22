package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"x-tunnel/internal/app"
)

var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

func main() {
	// 用独立 FlagSet：internal/app 的 init() 已把 x-tunnel 的旗标注册到
	// flag.CommandLine，这里再注册同名旗标会 panic。
	fs := flag.NewFlagSet("baidu-socks5", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON 配置文件路径")
	listen := fs.String("listen", "", "覆盖配置文件里的监听地址")
	showVersion := fs.Bool("version", false, "输出版本信息并退出")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("baidu-socks5 version=%s commit=%s build=%s\n", buildVersion, buildCommit, buildDate)
		return
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "缺少 -config")
		os.Exit(2)
	}

	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}
	if *listen != "" {
		config.Listen = *listen
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.RunBaiduSocks5(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "baidu-socks5 退出: %v\n", err)
		os.Exit(1)
	}
}

// loadConfig 读 JSON 配置。配置里含 X-T5-Auth 凭据，文件权限必须收紧到仅属主可读。
func loadConfig(path string) (app.BaiduSocks5Config, error) {
	var config app.BaiduSocks5Config
	info, err := os.Stat(path)
	if err != nil {
		return config, err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return config, fmt.Errorf("配置文件权限过宽（%04o），请 chmod 600：凭据不能被其他用户读到", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, err
	}
	return config, nil
}
