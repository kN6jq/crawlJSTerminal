// Package crawlJSTerminal -----------------------------
// @file      : main.go
// @author    : Xm17
// @contact   : https://github.com/kN6jq
// @time      : 2024/10/29 16:28
// -------------------------------------------
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/kN6jq/crawlJSTerminal/crawl"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	target         = flag.String("target", "", "目标域名 (必需)")
	keywords       = flag.String("keywords", "", "关键字列表，用逗号分隔")
	blackKeywords  = flag.String("black", "", "黑名单关键字列表，用逗号分隔")
	maxAPIs        = flag.Int("max-apis", 1000, "每个域名最大API数量")
	headers        = flag.String("headers", "", "自定义请求头，格式：'Header1:Value1,Header2:Value2'")
	minDelay       = flag.Duration("min-delay", 100*time.Millisecond, "请求最小延迟时间")
	maxDelay       = flag.Duration("max-delay", 2*time.Second, "请求最大延迟时间")
	maxConcurrency = flag.Int64("concurrency", 20, "最大并发请求数")
	workerCount    = flag.Int("workers", 20, "工作协程数量")
	outputFile     = flag.Bool("output", true, "是否输出结果到文件")
	version        = flag.Bool("version", false, "显示版本信息")
)

const VERSION = "v1.0.0"

func main() {
	// 添加命令行使用说明
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "JS爬虫工具 %s\n\n", VERSION)
		fmt.Fprintf(os.Stderr, "用法:\n")
		fmt.Fprintf(os.Stderr, "  %s [选项] -target example.com\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  %s -target example.com -keywords keyword1,keyword2 -black bad1,bad2\n", os.Args[0])
	}

	// 解析命令行参数
	flag.Parse()

	// 检查版本标志
	if *version {
		fmt.Printf("JS爬虫工具 %s\n", VERSION)
		os.Exit(0)
	}

	// 验证必需参数
	if *target == "" {
		fmt.Println("错误: 必须指定目标域名 (-target)")
		flag.Usage()
		os.Exit(1)
	}

	// 处理关键字列表
	var keywordsList []string
	if *keywords != "" {
		keywordsList = strings.Split(*keywords, ",")
	} else {
		// 如果未指定关键字，使用目标域名作为关键字
		keywordsList = []string{*target}
	}

	// 处理黑名单关键字列表
	var blackKeywordsList []string
	if *blackKeywords != "" {
		blackKeywordsList = strings.Split(*blackKeywords, ",")
	}

	// 创建结果通道
	resultChan := make(chan crawl.ResultItem, 10000)

	// 创建配置
	config := crawl.Config{
		Target:           *target,
		Keywords:         keywordsList,
		BlackKeywords:    blackKeywordsList,
		MaxAPIsPerDomain: *maxAPIs,
		Headers:          *headers,
		MinDelay:         *minDelay,
		MaxDelay:         *maxDelay,
		MaxConcurrency:   *maxConcurrency,
		WorkerCount:      *workerCount,
		OutputFile:       *outputFile,
		ResultChan:       resultChan,
	}

	// 创建一个可取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 创建爬虫实例
	crawler := crawl.NewJSINFO(config)

	// 在后台处理结果
	go func() {
		for result := range resultChan {
			switch result.Type {
			case "rootdomain":
				fmt.Printf("[+] 根域名: %v\n", result.Value)
			case "subdomain":
				fmt.Printf("[+] 子域名: %v\n", result.Value)
			case "api":
				fmt.Printf("[+] API: %v\n", result.Value)
			case "leakinfo":
				if info, ok := result.Value.(crawl.LeakInfo); ok {
					fmt.Printf("[!] 信息泄露: [%s] %s (来源: %s)\n", info.Type, info.Value, info.Source)
				}
			}
		}
	}()

	// 打印启动信息
	fmt.Printf("\nJS爬虫工具 %s\n", VERSION)
	fmt.Printf("目标: %s\n", *target)
	fmt.Printf("关键字: %v\n", keywordsList)
	fmt.Printf("黑名单关键字: %v\n", blackKeywordsList)
	fmt.Printf("最大并发: %d\n", *maxConcurrency)
	fmt.Printf("工作协程: %d\n", *workerCount)
	fmt.Println("\n开始扫描...\n")

	// 在goroutine中启动爬虫
	errChan := make(chan error, 1)
	go func() {
		errChan <- crawler.Start(ctx)
	}()

	// 等待信号或错误
	select {
	case <-sigChan:
		fmt.Println("\n收到终止信号，正在优雅关闭...")
		cancel()
	case err := <-errChan:
		if err != nil {
			log.Printf("爬虫错误: %v", err)
			os.Exit(1)
		}
	}

	fmt.Println("\n扫描完成!")
}
