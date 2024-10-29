// Package crawl -----------------------------
// @file      : crawl.go
// @author    : Xm17
// @contact   : https://github.com/kN6jq
// @time      : 2024/10/29 16:29
// -------------------------------------------
package crawl

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/panjf2000/ants/v2"
	"github.com/valyala/fasthttp"
	"golang.org/x/sync/semaphore"
	"sort"

	"log"
	"math/rand"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

type JSINFO struct {
	queue              chan string
	rootDomains        sync.Map
	subDomains         sync.Map
	apis               sync.Map
	apiCount           sync.Map
	leakInfos          sync.Map // 改为 sync.Map
	extractedURLs      sync.Map
	keywords           []string
	blackKeywords      []string
	blackExtendList    map[string]bool
	leakInfoPatterns   map[string]*regexp.Regexp
	subdomainRegex     *regexp.Regexp
	jsLinkRegex        *regexp.Regexp // 预编译 JS 链接正则表达式
	maxAPIsPerDomain   int
	customHeaders      map[string]string
	minDelay           time.Duration
	maxDelay           time.Duration
	sem                *semaphore.Weighted
	httpClient         *fasthttp.Client
	requestPool        sync.Pool
	responsePool       sync.Pool
	leakInfoBufferSize int
	leakInfoBuffer     chan LeakInfo
	mu                 sync.Mutex
	leakInfoMap        sync.Map
	config             Config
}

type LeakInfo struct {
	Type   string
	Value  string
	Source string
}

type ResultItem struct {
	Type  string // "rootdomain", "subdomain", "api", 或 "leakinfo"
	Value interface{}
}

type Config struct {
	Target           string
	Keywords         []string
	BlackKeywords    []string
	MaxAPIsPerDomain int
	CustomHeaders    map[string]string
	MinDelay         time.Duration
	MaxDelay         time.Duration
	MaxConcurrency   int64
	Headers          string
	ResultChan       chan<- ResultItem
	WorkerCount      int // 新增：可配置的 worker 数量
	OutputFile       bool
}

func NewJSINFO(config Config) *JSINFO {
	j := &JSINFO{
		queue:              make(chan string, 10000),
		blackExtendList:    make(map[string]bool),
		leakInfoPatterns:   make(map[string]*regexp.Regexp),
		maxAPIsPerDomain:   config.MaxAPIsPerDomain,
		minDelay:           config.MinDelay,
		maxDelay:           config.MaxDelay,
		keywords:           config.Keywords,
		blackKeywords:      config.BlackKeywords,
		customHeaders:      config.CustomHeaders,
		sem:                semaphore.NewWeighted(config.MaxConcurrency),
		leakInfoBufferSize: 1000,
		leakInfoBuffer:     make(chan LeakInfo, 1000),
		config:             config,
	}

	j.httpClient = &fasthttp.Client{
		TLSConfig: &tls.Config{InsecureSkipVerify: false},
	}

	j.requestPool = sync.Pool{
		New: func() interface{} {
			return fasthttp.AcquireRequest()
		},
	}

	j.responsePool = sync.Pool{
		New: func() interface{} {
			return fasthttp.AcquireResponse()
		},
	}
	if j.maxAPIsPerDomain == -1 {
		j.maxAPIsPerDomain = 1000
	}
	j.subdomainRegex = regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\.[a-zA-Z0-9-\.]+`)
	j.jsLinkRegex = regexp.MustCompile(`(https?:)?//[^\s/$.?#].[^\s]*`) // 预编译 JS 链接正则表达式
	blackExtends := []string{"png", "jpg", "gif", "jpeg", "ico", "svg", "bmp", "mp3", "mp4", "avi", "mpeg", "mpg", "mov", "zip", "rar", "tar", "gz", "css", "woff", "ttf", "eot", "pdf"}
	for _, ext := range blackExtends {
		j.blackExtendList[ext] = true
	}

	j.customHeaders = make(map[string]string)
	for _, pair := range strings.Split(config.Headers, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
		if len(parts) == 2 {
			j.customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	j.initLeakInfoPatterns()

	if !strings.HasPrefix(config.Target, "http://") && !strings.HasPrefix(config.Target, "https://") {
		j.queue <- "http://" + config.Target
	} else {
		j.queue <- config.Target
	}

	go j.processLeakInfoBuffer()

	log.Printf("JSINFO initialized: target=%s, keywords=%v, blackKeywords=%v, maxAPIsPerDomain=%d, customHeaders=%v, minDelay=%v, maxDelay=%v, maxConcurrency=%d",
		config.Target, config.Keywords, config.BlackKeywords, config.MaxAPIsPerDomain, config.CustomHeaders, config.MinDelay, config.MaxDelay, config.MaxConcurrency)

	return j
}

func (j *JSINFO) processLeakInfoBuffer() {
	for leakInfo := range j.leakInfoBuffer {
		j.addLeakInfo(leakInfo.Type, leakInfo.Value, leakInfo.Source)
	}
}

func (j *JSINFO) initLeakInfoPatterns() {
	patterns := map[string]string{
		"wechat_corpsecret_key":      `(?i)corpsecret\s*[:=]\s*["']?([a-z0-9\-]+)["']?`,
		"password":                   `(?i)(password\s*[` + "`" + `=:"]+\s*[^\s]+|password is\s*[` + "`" + `=:"]*\s*[^\s]+|pwd\s*[` + "`" + `=:"]*\s*[^\s]+|passwd\s*[` + "`" + `=:"]+\s*[^\s]+)`,
		"phone":                      `[^0-9]1(?:3\d|4[4-9]|5[0-35-9]|6[2567]|7[0-8]|8\d|9[0-35-9])\d{8}[^0-9]`,
		"IdCard":                     `[^0-9]([1-9]\d{5}(?:18|19|20)?\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?:\d|X|x)?)[^0-9]`,
		"mail":                       `([-_a-zA-Z0-9\.]{1,64}@[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})`,
		"json_web_token":             `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`,
		"SSH_privKey":                `([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`,
		"AlibabaAccessKeyID":         `^LTAI[A-Z0-9]{12,20}$`,
		"AlibabaAccessKeySecret":     `^[A-Za-z0-9]{30}$`,
		"TencentSecretId":            `^AKID[A-Za-z0-9]{13}$`,
		"TencentSecretKey":           `^[A-Za-z0-9]{40}$`,
		"BaiduAccessKey":             `^AK[A-Za-z0-9]{10,40}$`,
		"JDCloudAccessKey":           `^JDC_[A-Z0-9]{28,32}$`,
		"VolcengineAccessKey":        `^AKLT[a-zA-Z0-9-_]{0,252}$`,
		"UCloudAccessKey":            `^UC[A-Za-z0-9]{10,40}$`,
		"QingCloudAccessKey":         `^QY[A-Za-z0-9]{10,40}$`,
		"KingsoftCloudAccessKey":     `^AKLT[a-zA-Z0-9-_]{16,28}`,
		"ChinaUnicomCloudAccessKey":  `^LTC[A-Za-z0-9]{10,60}$`,
		"ChinaMobileCloudAccessKey":  `^YD[A-Za-z0-9]{10,60}$`,
		"ChinaTelecomCloudAccessKey": `^CTC[A-Za-z0-9]{10,60}$`,
		"YiYunTongCloudAccessKey":    `^YYT[A-Za-z0-9]{10,60}$`,
		"YonyouCloudAccessKey":       `^YY[A-Za-z0-9]{10,40}$`,
		"OUCDCAccessKey":             `^CI[A-Za-z0-9]{10,40}$`,
		"GCoreLabsAccessKey":         `^gcore[A-Za-z0-9]{10,30}$`,
	}

	for key, pattern := range patterns {
		j.leakInfoPatterns[key] = regexp.MustCompile(pattern)
	}
}

func (j *JSINFO) Start(ctx context.Context) error {
	var wg sync.WaitGroup
	workerCount := j.config.WorkerCount
	if workerCount == 0 {
		workerCount = 20 // 默认值
	}
	p, err := ants.NewPool(workerCount, ants.WithPreAlloc(true))
	if err != nil {
		return fmt.Errorf("failed to create worker pool: %v", err)
	}
	defer p.Release()

	newURLs := make(chan string, 10000)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		err := p.Submit(func() {
			defer wg.Done()
			for {
				select {
				case url, ok := <-j.queue:
					if !ok {
						return
					}
					if err := j.sem.Acquire(ctx, 1); err != nil {
						log.Printf("Failed to acquire semaphore: %v", err)
						return
					}
					j.processURLSafe(ctx, url, newURLs)
					j.sem.Release(1)
				case <-ctx.Done():
					return
				}
			}
		})
		if err != nil {
			cancel()
			return fmt.Errorf("failed to submit task to worker pool: %v", err)
		}
	}

	go func() {
		defer close(j.queue)
		for {
			select {
			case url, ok := <-newURLs:
				if !ok {
					return
				}
				select {
				case j.queue <- url:
				default:
					// Queue is full, discard URL
				}
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				if len(j.queue) == 0 {
					return
				}
			}
		}
	}()

	wg.Wait()

	j.printResults()
	return nil
}

func (j *JSINFO) processURLSafe(ctx context.Context, urlStr string, newURLs chan<- string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in processURLSafe: error=%v, url=%s", r, urlStr)
			panic(r) // 重新抛出 panic 以便更好地调试
		}
	}()
	if _, exists := j.extractedURLs.Load(urlStr); exists {
		return
	}
	j.extractedURLs.Store(urlStr, true)

	log.Printf("Processing URL: %s", urlStr)

	delay := j.minDelay + time.Duration(rand.Int63n(int64(j.maxDelay-j.minDelay)))
	time.Sleep(delay)

	retryCount := 0
	maxRetries := 3

	for retryCount < maxRetries {
		select {
		case <-ctx.Done():
			return
		default:
			req := j.requestPool.Get().(*fasthttp.Request)
			resp := j.responsePool.Get().(*fasthttp.Response)
			defer j.requestPool.Put(req)
			defer j.responsePool.Put(resp)

			req.SetRequestURI(urlStr)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
			for key, value := range j.customHeaders {
				req.Header.Set(key, value)
			}

			timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			errCh := make(chan error, 1)
			go func() {
				errCh <- j.httpClient.Do(req, resp)
			}()

			select {
			case err := <-errCh:
				if err != nil {
					retryCount++
					if retryCount >= maxRetries {
						log.Printf("Failed to fetch URL after max retries: url=%s, error=%v", urlStr, err)
						return
					}
					log.Printf("Failed to fetch URL, retrying: url=%s, retry=%d, error=%v", urlStr, retryCount, err)
					time.Sleep(time.Second * time.Duration(retryCount))
					continue
				}
			case <-timeoutCtx.Done():
				log.Printf("Request timed out: url=%s", urlStr)
				retryCount++
				if retryCount >= maxRetries {
					log.Printf("Failed to fetch URL after max retries due to timeouts: url=%s", urlStr)
					return
				}
				continue
			}

			contentType := string(resp.Header.Peek("Content-Type"))

			if strings.HasPrefix(contentType, "application/javascript") || strings.HasPrefix(contentType, "text/javascript") {
				j.processJS(ctx, resp.Body(), urlStr, newURLs)
			} else {
				j.processHTML(ctx, resp.Body(), urlStr, newURLs)
			}
			return
		}
	}
}

func (j *JSINFO) extractLinkSafe(ctx context.Context, baseURL, link string, newURLs chan<- string) {
	if link == "" {
		return
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		log.Printf("Failed to parse base URL: url=%s, error=%v", baseURL, err)
		return
	}

	u, err := url.Parse(link)
	if err != nil {
		log.Printf("Failed to parse link: link=%s, error=%v", link, err)
		return
	}

	resolvedURL := base.ResolveReference(u)

	if strings.HasSuffix(strings.ToLower(resolvedURL.Path), ".js") {
		filename := path.Base(resolvedURL.Path)
		lowercaseFilename := strings.ToLower(filename)
		if j.isCommonJSLibrary(lowercaseFilename) {
			return
		}
	}

	if !j.isValidDomain(resolvedURL.Hostname()) {
		return
	}

	j.addRootDomain(resolvedURL.Hostname())
	j.addSubDomain(resolvedURL.Hostname())

	if !j.isBlacklistedExtension(resolvedURL.Path) {
		j.addAPI(resolvedURL.String())
		if _, exists := j.extractedURLs.Load(resolvedURL.String()); !exists {
			apiCount, _ := j.apiCount.LoadOrStore(resolvedURL.Hostname(), 0)
			if apiCount.(int) < j.maxAPIsPerDomain {
				select {
				case newURLs <- resolvedURL.String():
				case <-ctx.Done():
					return
				default:
					// Channel is full, discard URL
				}
				j.apiCount.Store(resolvedURL.Hostname(), apiCount.(int)+1)
			}
		}
	}
}

func (j *JSINFO) isCommonJSLibrary(filename string) bool {
	commonLibraries := []string{
		"jquery.min.js",
		"jquery.js",
		"bootstrap.min.js",
		"bootstrap.js",
		"angular.min.js",
		"angular.js",
		"react.min.js",
		"react.js",
		"vue.min.js",
		"vue.js",
		"halo-comment.min.js",
		"jsformat.js",
		"jsendecode.js",
		"journals.min.js",
		"tocbot.min.js",
		"post.min.js",
	}

	for _, lib := range commonLibraries {
		if filename == lib {
			return true
		}
	}
	return false
}

func (j *JSINFO) processHTML(ctx context.Context, body []byte, urlStr string, newURLs chan<- string) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		log.Printf("Error parsing HTML for %s: %v", urlStr, err)
		return
	}

	j.findLinksInHTML(ctx, doc, urlStr, newURLs)
	j.findLeakInfo(string(body), urlStr)
}

func (j *JSINFO) processJS(ctx context.Context, body []byte, urlStr string, newURLs chan<- string) {
	j.findLinksInJS(ctx, string(body), urlStr, newURLs)
	j.findLeakInfo(string(body), urlStr)
}

func (j *JSINFO) findLinksInHTML(ctx context.Context, doc *goquery.Document, baseURL string, newURLs chan<- string) {
	doc.Find("a[href], script[src], link[href]").Each(func(i int, s *goquery.Selection) {
		select {
		case <-ctx.Done():
			return
		default:
			link, exists := s.Attr("href")
			if !exists {
				link, _ = s.Attr("src")
			}
			j.extractLinkSafe(ctx, baseURL, link, newURLs)
		}
	})
}

func (j *JSINFO) findLinksInJS(ctx context.Context, jsContent, baseURL string, newURLs chan<- string) {
	matches := j.jsLinkRegex.FindAllString(jsContent, -1)
	for _, match := range matches {
		select {
		case <-ctx.Done():
			return
		default:
			j.extractLinkSafe(ctx, baseURL, match, newURLs)
		}
	}
	j.extractSubdomainsFromJS(jsContent)
}

func (j *JSINFO) extractSubdomainsFromJS(content string) {
	matches := j.subdomainRegex.FindAllString(content, -1)
	for _, match := range matches {
		cleanedDomain := j.cleanSubdomain(match)
		if cleanedDomain != "" && j.isValidDomain(cleanedDomain) {
			j.addSubDomain(cleanedDomain)
		}
	}
}

func (j *JSINFO) cleanSubdomain(s string) string {
	doubleQuoteIndex := strings.Index(s, "\"")
	singleQuoteIndex := strings.Index(s, "'")

	if doubleQuoteIndex != -1 {
		s = s[:doubleQuoteIndex]
	}
	if singleQuoteIndex != -1 && (singleQuoteIndex < doubleQuoteIndex || doubleQuoteIndex == -1) {
		s = s[:singleQuoteIndex]
	}

	s = strings.TrimLeft(s, "\"'(),;:")

	colonIndex := strings.LastIndex(s, ":")
	if colonIndex != -1 {
		afterColon := strings.ToLower(s[colonIndex+1:])
		if strings.HasPrefix(afterColon, "http") || strings.HasPrefix(afterColon, "https") {
			s = s[:colonIndex]
		}
	}

	s = strings.TrimRight(s, "\"'(),;:")
	s = strings.TrimSpace(s)

	if strings.HasPrefix(strings.ToLower(s), "u002f") {
		s = s[5:]
	}

	parts := strings.Split(s, ".")

	if len(parts) < 2 {
		return ""
	}

	return s
}

func (j *JSINFO) isValidDomain(domain string) bool {
	for _, keyword := range j.keywords {
		if strings.Contains(domain, keyword) {
			return true
		}
	}
	return false
}

func (j *JSINFO) addRootDomain(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		rootDomain := parts[len(parts)-2] + "." + parts[len(parts)-1]
		for _, keyword := range j.config.Keywords {
			if strings.Contains(rootDomain, keyword) {
				// 确保同时存储到 rootDomains sync.Map 中
				if _, exists := j.rootDomains.LoadOrStore(rootDomain, true); !exists {
					select {
					case j.config.ResultChan <- ResultItem{Type: "rootdomain", Value: rootDomain}:
						log.Printf("发现新的根域名: %s", rootDomain)
						// 确保值被正确存储
						j.rootDomains.Store(rootDomain, rootDomain)
						return true
					default:
						log.Printf("结果通道已满，无法添加根域名: %s", rootDomain)
					}
				}
				return false
			}
		}
	}
	return false
}

func (j *JSINFO) addSubDomain(domain string) bool {
	for _, keyword := range j.config.Keywords {
		if strings.Contains(domain, keyword) {
			if _, exists := j.subDomains.LoadOrStore(domain, true); !exists {
				select {
				case j.config.ResultChan <- ResultItem{Type: "subdomain", Value: domain}:
					log.Printf("发现新的子域名: %s", domain)
					return true
				default:
					log.Printf("结果通道已满，无法添加子域名: %s", domain)
				}
			}
			return false
		}
	}
	return false
}

func (j *JSINFO) addAPI(api string) bool {
	u, err := url.Parse(api)
	if err != nil {
		log.Printf("解析API URL失败: url=%s, 错误=%v", api, err)
		return false
	}

	hostname := u.Hostname()
	for _, keyword := range j.config.Keywords {
		if strings.Contains(hostname, keyword) {
			if _, exists := j.apis.LoadOrStore(api, true); !exists {
				count, _ := j.apiCount.LoadOrStore(hostname, 0)
				currentCount := count.(int)
				if currentCount < j.config.MaxAPIsPerDomain {
					select {
					case j.config.ResultChan <- ResultItem{Type: "api", Value: api}:
						j.apiCount.Store(hostname, currentCount+1)
						log.Printf("发现新的API: api=%s, 计数=%d, 最大值=%d, 主机名=%s", api, currentCount+1, j.config.MaxAPIsPerDomain, hostname)
						return true
					default:
						log.Printf("结果通道已满，无法添加API: %s", api)
					}
				}
			}
			return false
		}
	}
	return false
}

func (j *JSINFO) addLeakInfo(leakType, value, source string) bool {
	// 检查黑名单关键字
	for _, blackKeyword := range j.config.BlackKeywords {
		if strings.Contains(value, blackKeyword) {
			return false
		}
	}

	// 创建唯一键
	key := fmt.Sprintf("%s:%s:%s", leakType, value, source)
	leakInfo := LeakInfo{
		Type:   leakType,
		Value:  value,
		Source: source,
	}

	// 同时存储到 leakInfoMap 和 leakInfos
	if _, exists := j.leakInfoMap.LoadOrStore(key, leakInfo); !exists {
		// 同时存储到 leakInfos 中，用于文件输出
		j.leakInfos.Store(key, leakInfo)

		select {
		case j.config.ResultChan <- ResultItem{Type: "leakinfo", Value: leakInfo}:
			log.Printf("发现新的泄露信息: 类型=%s, 值=%s, 来源=%s", leakType, value, source)
			return true
		default:
			log.Printf("结果通道已满，无法添加泄露信息: 类型=%s, 值=%s, 来源=%s", leakType, value, source)
		}
	}

	return false
}

func (j *JSINFO) isBlacklistedExtension(urlPath string) bool {
	ext := strings.ToLower(path.Ext(urlPath))
	if ext != "" {
		ext = ext[1:] // 移除前导点
		return j.blackExtendList[ext]
	}
	return false
}

func (j *JSINFO) isProcessed(urlStr string) bool {
	_, loaded := j.extractedURLs.LoadOrStore(urlStr, true)
	return loaded
}

func (j *JSINFO) printResults() {
	var rootDomainsCount, subDomainsCount, apisCount, leakInfosCount int

	// 计算根域名数量
	j.rootDomains.Range(func(key, value interface{}) bool {
		rootDomainsCount++
		return true
	})

	// 计算子域名数量
	j.subDomains.Range(func(key, value interface{}) bool {
		subDomainsCount++
		return true
	})

	// 计算 API 数量
	j.apis.Range(func(key, value interface{}) bool {
		apisCount++
		return true
	})

	// 计算泄露信息数量
	j.leakInfos.Range(func(key, value interface{}) bool {
		leakInfosCount++
		return true
	})

	// 打印详细的扫描结果
	log.Printf("\n扫描结果统计:")
	log.Printf("- 根域名: %d 个", rootDomainsCount)
	log.Printf("- 子域名: %d 个", subDomainsCount)
	log.Printf("- APIs: %d 个", apisCount)
	log.Printf("- 信息泄露: %d 条", leakInfosCount)

	if j.config.OutputFile {
		timestamp := time.Now().Unix()
		// 只在有数据时才创建文件
		if rootDomainsCount > 0 {
			j.writeToFile(fmt.Sprintf("%d_rootdomain.txt", timestamp), &j.rootDomains)
		}
		if subDomainsCount > 0 {
			j.writeToFile(fmt.Sprintf("%d_subdomain.txt", timestamp), &j.subDomains)
		}
		if apisCount > 0 {
			j.writeToFile(fmt.Sprintf("%d_apis.txt", timestamp), &j.apis)
		}
		if leakInfosCount > 0 {
			j.writeLeakInfoToFile(fmt.Sprintf("%d_leakinfos.txt", timestamp), &j.leakInfos)
		}
		log.Println("\n结果已写入到相应的文件中.")
	} else {
		log.Println("\n文件输出已禁用，结果仅打印到控制台.")
	}
}

func (j *JSINFO) findLeakInfo(content, source string) {
	for patternName, pattern := range j.leakInfoPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {

			j.addLeakInfo(patternName, match, source)
		}
	}
}

func (j *JSINFO) writeToFile(filename string, data *sync.Map) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create file: filename=%s, error=%v", filename, err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	var count int

	// 收集所有条目
	var entries []string
	data.Range(func(key, value interface{}) bool {
		// 将 value 转换为字符串
		var entry string
		switch v := value.(type) {
		case string:
			entry = v
		case LeakInfo:
			entry = fmt.Sprintf("%s: %s", v.Type, v.Value)
		default:
			entry = fmt.Sprint(key)
		}
		entries = append(entries, entry)
		count++
		return true
	})

	// 排序条目以保证输出稳定性
	sort.Strings(entries)

	// 写入文件
	for _, entry := range entries {
		if _, err := fmt.Fprintln(writer, entry); err != nil {
			log.Printf("Failed to write to file: filename=%s, error=%v", filename, err)
		}
	}

	if err := writer.Flush(); err != nil {
		log.Printf("Failed to flush writer: error=%v", err)
		return
	}

	// 根据文件类型打印不同的日志信息
	fileType := strings.TrimPrefix(filename[strings.LastIndex(filename, "_")+1:], "_")
	log.Printf("文件已创建: 类型=%s, 文件名=%s, 条目数=%d", fileType, filename, count)
}

func (j *JSINFO) writeLeakInfoToFile(filename string, leakInfos *sync.Map) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create leak info file: filename=%s, error=%v", filename, err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	var count int

	// 按类型分组存储泄露信息
	typeGroups := make(map[string][]LeakInfo)

	leakInfos.Range(func(_, value interface{}) bool {
		if info, ok := value.(LeakInfo); ok {
			typeGroups[info.Type] = append(typeGroups[info.Type], info)
			count++
		}
		return true
	})

	// 遍历每个类型，写入文件
	for leakType, infos := range typeGroups {
		// 写入类型标题
		_, err := fmt.Fprintf(writer, "\n[%s]\n", leakType)
		if err != nil {
			log.Printf("Failed to write leak info type to file: error=%v", err)
			continue
		}

		// 写入该类型下的所有泄露信息
		for _, info := range infos {
			_, err := fmt.Fprintf(writer, "Value: %s\nSource: %s\n---\n", info.Value, info.Source)
			if err != nil {
				log.Printf("Failed to write leak info to file: error=%v", err)
				continue
			}
		}
	}

	if err := writer.Flush(); err != nil {
		log.Printf("Failed to flush writer: error=%v", err)
		return
	}

	log.Printf("Leak info file created: filename=%s, leakInfoCount=%d", filename, count)
}
