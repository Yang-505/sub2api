// Package ip 提供客户端 IP 地址提取工具。
package ip

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

const clientIPResolutionKey = "sub2api.client_ip_resolution"

// ClientIPResolution 保存客户端 IP、连接对端和解析来源，不保存原始请求头。
type ClientIPResolution struct {
	ClientIP string
	PeerIP   string
	Source   string
}

type forwardedIPSettings struct {
	trustForwarded bool
	headers        []string
	trustedProxies *CompiledIPRules
}

// SetForwardedIPSettings snapshots the forwarded-IP mode and custom header list
// for this request. 转发头仅在对端匹配可信代理规则时生效；缺少规则时使用 Gin 的安全解析。
// 同时固定解析结果，避免下游修改请求头导致日志与认证使用不同的 IP。
func SetForwardedIPSettings(c *gin.Context, enabled bool, headers []string, trustedProxies ...*CompiledIPRules) {
	if c == nil {
		return
	}
	settings := forwardedIPSettings{
		trustForwarded: enabled,
		headers:        append([]string(nil), headers...),
	}
	if len(trustedProxies) > 0 {
		settings.trustedProxies = trustedProxies[0]
	}
	c.Set(clientIPResolutionKey, resolveClientIP(c, settings))
}

// SetLegacyForwardedIPTrust records the forwarded-header compatibility mode.
// 保留旧调用接口，但不会跳过可信代理检查或直接信任原始转发头。
func SetLegacyForwardedIPTrust(c *gin.Context, enabled bool) {
	SetForwardedIPSettings(c, enabled, nil)
}

// GetClientIP 返回经过可信代理检查的客户端 IP，与安全校验和请求日志共用请求快照。
func GetClientIP(c *gin.Context) string {
	return GetClientIPResolution(c).ClientIP
}

// GetClientIPResolution 返回当前请求固定的 IP 及来源；未注入时回退 Gin 的可信代理链。
func GetClientIPResolution(c *gin.Context) ClientIPResolution {
	if c == nil {
		return ClientIPResolution{}
	}
	if value, ok := c.Get(clientIPResolutionKey); ok {
		if resolution, ok := value.(ClientIPResolution); ok {
			return resolution
		}
	}
	return resolveClientIP(c, forwardedIPSettings{})
}

// resolveClientIP 先校验连接对端，再按配置选择可信转发头；私网地址也必须经过相同校验。
func resolveClientIP(c *gin.Context, settings forwardedIPSettings) ClientIPResolution {
	if c == nil || c.Request == nil {
		return ClientIPResolution{}
	}
	peerIP := normalizeValidIP(c.Request.RemoteAddr)
	result := ClientIPResolution{ClientIP: peerIP, PeerIP: peerIP, Source: "remote_addr"}
	if peerIP == "" {
		return result
	}
	if settings.trustedProxies == nil {
		result.ClientIP = GetTrustedClientIP(c)
		if result.ClientIP != peerIP {
			result.Source = "trusted_proxy_chain"
		}
		return result
	}
	if !matchesCompiledRules(net.ParseIP(peerIP), settings.trustedProxies) {
		return result
	}

	headers := []string{"X-Forwarded-For", "X-Real-IP"}
	if settings.trustForwarded {
		headers = append(append([]string(nil), settings.headers...), "CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For")
	}
	for _, header := range headers {
		clientIP := resolveForwardedHeaderIP(c, header, settings.trustedProxies)
		if clientIP != "" {
			result.ClientIP = clientIP
			result.Source = "header:" + strings.ToLower(header)
			return result
		}
	}
	return result
}

// resolveForwardedHeaderIP 验证完整 IP 链，从右侧剥离可信代理，停在第一个不可信地址。
// CF-Connecting-IP 和 X-Real-IP 只能包含单个 IP，重复头、端口和非法值均不采用。
func resolveForwardedHeaderIP(c *gin.Context, header string, trustedProxies *CompiledIPRules) string {
	values := c.Request.Header.Values(header)
	if len(values) == 0 {
		return ""
	}
	if strings.EqualFold(header, "CF-Connecting-IP") || strings.EqualFold(header, "X-Real-IP") {
		if len(values) != 1 {
			return ""
		}
		if parsed := net.ParseIP(strings.TrimSpace(values[0])); parsed != nil {
			return parsed.String()
		}
		return ""
	}
	candidates := strings.Split(strings.Join(values, ","), ",")
	parsed := make([]net.IP, len(candidates))
	for i, candidate := range candidates {
		parsed[i] = net.ParseIP(strings.TrimSpace(candidate))
		if parsed[i] == nil {
			return ""
		}
	}
	for i := len(parsed) - 1; i >= 0; i-- {
		if i == 0 || !matchesCompiledRules(parsed[i], trustedProxies) {
			return parsed[i].String()
		}
	}
	return ""
}

// GetTrustedClientIP 从 Gin 的可信代理解析链提取客户端 IP。
// 该方法依赖 gin.Engine.SetTrustedProxies 配置，不会优先直接信任原始转发头值。
// 适用于 ACL / 风控等安全敏感场景。
func GetTrustedClientIP(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return normalizeIP(c.ClientIP())
}

// GetSecurityClientIP returns the address used by security-sensitive paths.
// 优先使用已校验可信代理的请求快照；缺少快照时安全回退 Gin 的可信代理链。
// 保留旧开关参数以兼容现有调用，实际解析模式以请求入口的快照为准。
func GetSecurityClientIP(c *gin.Context, _ bool) string {
	return GetClientIP(c)
}

// normalizeIP 规范化 IP 地址，去除端口号和空格。
func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	// 移除端口号（如 "192.168.1.1:8080" -> "192.168.1.1"）
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}

// normalizeValidIP 规范化并验证连接地址，避免把 unknown、主机名等非法值传给安全服务。
func normalizeValidIP(value string) string {
	normalized := normalizeIP(value)
	parsed := net.ParseIP(normalized)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

// CompiledIPRules 表示预编译的 IP 匹配规则。
// PatternCount 记录原始规则数量，用于保留“规则存在但全无效”时的行为语义。
type CompiledIPRules struct {
	CIDRs        []*net.IPNet
	IPs          []net.IP
	PatternCount int
}

// CompileIPRules 将 IP/CIDR 字符串规则预编译为可复用结构。
// 非法规则会被忽略，但 PatternCount 会保留原始规则条数。
func CompileIPRules(patterns []string) *CompiledIPRules {
	compiled := &CompiledIPRules{
		CIDRs:        make([]*net.IPNet, 0, len(patterns)),
		IPs:          make([]net.IP, 0, len(patterns)),
		PatternCount: len(patterns),
	}
	for _, pattern := range patterns {
		normalized := strings.TrimSpace(pattern)
		if normalized == "" {
			continue
		}
		if strings.Contains(normalized, "/") {
			_, cidr, err := net.ParseCIDR(normalized)
			if err != nil || cidr == nil {
				continue
			}
			compiled.CIDRs = append(compiled.CIDRs, cidr)
			continue
		}
		parsedIP := net.ParseIP(normalized)
		if parsedIP == nil {
			continue
		}
		compiled.IPs = append(compiled.IPs, parsedIP)
	}
	return compiled
}

func matchesCompiledRules(parsedIP net.IP, rules *CompiledIPRules) bool {
	if parsedIP == nil || rules == nil {
		return false
	}
	for _, cidr := range rules.CIDRs {
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	for _, ruleIP := range rules.IPs {
		if parsedIP.Equal(ruleIP) {
			return true
		}
	}
	return false
}

// MatchesPattern 检查 IP 是否匹配指定的模式（支持单个 IP 或 CIDR）。
// pattern 可以是：
// - 单个 IP: "192.168.1.100"
// - CIDR 范围: "192.168.1.0/24"
func MatchesPattern(clientIP, pattern string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	// 尝试解析为 CIDR
	if strings.Contains(pattern, "/") {
		_, cidr, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)
	}

	// 作为单个 IP 处理
	patternIP := net.ParseIP(pattern)
	if patternIP == nil {
		return false
	}
	return ip.Equal(patternIP)
}

// MatchesAnyPattern 检查 IP 是否匹配任意一个模式。
func MatchesAnyPattern(clientIP string, patterns []string) bool {
	for _, pattern := range patterns {
		if MatchesPattern(clientIP, pattern) {
			return true
		}
	}
	return false
}

// CheckIPRestriction 检查 IP 是否被 API Key 的 IP 限制允许。
// 返回值：(是否允许, 拒绝原因)
// 逻辑：
// 1. 先检查黑名单，如果在黑名单中则直接拒绝
// 2. 如果白名单不为空，IP 必须在白名单中
// 3. 如果白名单为空，允许访问（除非被黑名单拒绝）
func CheckIPRestriction(clientIP string, whitelist, blacklist []string) (bool, string) {
	return CheckIPRestrictionWithCompiledRules(
		clientIP,
		CompileIPRules(whitelist),
		CompileIPRules(blacklist),
	)
}

// CheckIPRestrictionWithCompiledRules 使用预编译规则检查 IP 是否允许访问。
func CheckIPRestrictionWithCompiledRules(clientIP string, whitelist, blacklist *CompiledIPRules) (bool, string) {
	// 规范化 IP
	clientIP = normalizeIP(clientIP)
	if clientIP == "" {
		return false, "access denied"
	}
	parsedIP := net.ParseIP(clientIP)
	if parsedIP == nil {
		return false, "access denied"
	}

	// 1. 检查黑名单
	if blacklist != nil && blacklist.PatternCount > 0 && matchesCompiledRules(parsedIP, blacklist) {
		return false, "access denied"
	}

	// 2. 检查白名单（如果设置了白名单，IP 必须在其中）
	if whitelist != nil && whitelist.PatternCount > 0 && !matchesCompiledRules(parsedIP, whitelist) {
		return false, "access denied"
	}

	return true, ""
}

// ValidateIPPattern 验证 IP 或 CIDR 格式是否有效。
func ValidateIPPattern(pattern string) bool {
	if strings.Contains(pattern, "/") {
		_, _, err := net.ParseCIDR(pattern)
		return err == nil
	}
	return net.ParseIP(pattern) != nil
}

// ValidateIPPatterns 验证多个 IP 或 CIDR 格式。
// 返回无效的模式列表。
func ValidateIPPatterns(patterns []string) []string {
	var invalid []string
	for _, p := range patterns {
		if !ValidateIPPattern(p) {
			invalid = append(invalid, p)
		}
	}
	return invalid
}
