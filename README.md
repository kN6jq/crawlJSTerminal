# JS爬虫工具 (JSCrawler)

一个用于自动爬取和分析网站 JavaScript 文件的工具，可以发现子域名、API接口和敏感信息。

## 功能特点

- 🔍 自动爬取目标网站的 JavaScript 文件
- 🌐 发现并收集子域名信息
- 📡 识别和提取 API 接口
- 🔒 检测敏感信息泄露
- ⚡ 支持多线程并发扫描
- 🎯 自定义关键字和黑名单过滤
- 📝 结果支持文件输出

## 敏感信息检测类型

注: 误报会慢慢改善

- 手机号码
- 身份证号
- 邮箱地址
- 密码信息
- JSON Web Token
- SSH 私钥
- 各类云服务 AccessKey
    - 阿里云
    - 腾讯云
    - 百度云
    - 京东云
    - 火山引擎
    - 更多...

## 安装

```bash
git clone https://github.com/kN6jq/crawlJSTerminal.git
cd crawlJSTerminal
go build
```

## 使用方法

### 基本用法

```bash
./crawlJSTerminal -target example.com
```

### 完整参数说明

```bash
选项:
  -target string
        目标域名 (必需)
  -keywords string
        关键字列表，用逗号分隔 (默认使用目标域名)
  -black string
        黑名单关键字列表，用逗号分隔
  -max-apis int
        每个域名最大API数量 (默认 1000)
  -headers string
        自定义请求头，格式：'Header1:Value1,Header2:Value2'
  -min-delay duration
        请求最小延迟时间 (默认 100ms)
  -max-delay duration
        请求最大延迟时间 (默认 2s)
  -concurrency int
        最大并发请求数 (默认 20)
  -workers int
        工作协程数量 (默认 20)
  -output
        是否输出结果到文件 (默认 true)
  -version
        显示版本信息
```

### 使用示例

1. 基本扫描：
```bash
./crawlJSTerminal -target example.com
```

2. 指定关键字：
```bash
./crawlJSTerminal -target example.com -keywords api,admin,internal
```

3. 设置黑名单：
```bash
./crawlJSTerminal -target example.com -black test,dev
```

4. 调整并发和延迟：
```bash
./crawlJSTerminal -target example.com -concurrency 30 -min-delay 200ms -max-delay 1s
```

5. 自定义请求头：
```bash
./crawlJSTerminal -target example.com -headers "User-Agent: CustomBot,Authorization: Bearer token"
```

## 输出结果

工具运行时会实时显示发现的信息：
- 根域名
- 子域名
- API 接口
- 敏感信息泄露

如果启用了文件输出（默认开启），会在当前目录生成以下文件：
- `{timestamp}_rootdomain.txt`: 根域名列表
- `{timestamp}_subdomain.txt`: 子域名列表
- `{timestamp}_apis.txt`: API接口列表
- `{timestamp}_leakinfos.txt`: 敏感信息列表

## 注意事项

1. 请合法使用本工具，仅用于授权的安全测试
2. 建议适当调整延迟参数，避免对目标服务器造成压力
3. 使用黑名单关键字可以过滤掉不需要的结果
4. 大型网站扫描可能需要较长时间，请耐心等待

## 贡献

欢迎提交 Issue 和 Pull Request 来帮助改进这个工具。

## 许可证

本项目基于 MIT 许可证开源。

## 联系方式

作者：Xm17
GitHub：https://github.com/kN6jq

## 免责声明

本工具仅用于合法的安全测试，使用本工具进行未授权的测试造成的任何后果由使用者承担。