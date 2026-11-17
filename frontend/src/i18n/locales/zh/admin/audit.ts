export default {
  audit: {
    title: '操作日志',
    description: '记录管理员与用户的管理面操作，请求头凭证仅保留首尾、请求体已脱敏。日志无法单条删除，全量清理需二次验证。',
    clearAll: '全部清理',
    empty: '暂无操作日志',
    loadFailed: '加载操作日志失败',
    filters: {
      all: '全部',
      q: '关键字',
      qPlaceholder: '路径 / 动作 / 操作者邮箱',
      actorEmail: '操作者邮箱',
      action: '动作',
      clientIp: '客户端 IP',
      method: '请求方法',
      authMethod: '认证方式',
      result: '结果',
      resultSuccess: '成功',
      resultFailure: '失败',
      startTime: '开始时间',
      endTime: '结束时间'
    },
    columns: {
      time: '时间',
      actor: '操作者',
      action: '动作',
      method: '方法',
      result: '结果',
      clientIp: '客户端 IP',
      detail: '详情'
    },
    detail: {
      title: '操作日志详情',
      actorRole: '角色',
      methodPath: '方法 / 路径',
      latency: '耗时',
      requestId: '请求 ID',
      peerIp: '连接对端 IP',
      clientIpSource: 'IP 解析来源',
      credential: '凭证（掩码）',
      userAgent: 'User-Agent',
      requestBody: '请求体（已脱敏）',
      extra: '附加信息'
    },
    ipProtection: {
      title: 'IP 封禁管理', block: '封禁 IP', unblock: '解除封禁',
      scopeHint: '封禁会限制这个 IP 下所有账号的登录和接口请求。请核对客户端 IP 与连接来源，旧日志可能缺少可信来源信息。',
      autoStatus: '自动封禁',
      rules: '异常阈值：{shortMinutes} 分钟失败 {short} 次，或 {longHours} 小时失败 {long} 次',
      penalties: '首次封禁 {initialMinutes} 分钟，再次触发封禁 {repeatHours} 小时',
      autoPermanent: '第 {count} 次触发后升级为永久封禁',
      noAutoPermanent: '自动永久封禁已关闭，可手动永久封禁',
      configHint: '默认只检测并列入可疑 IP，由管理员确认封禁。自动封禁需确认真实 IP 后通过 security.auth_abuse.enabled 启用；检测开关为 security.auth_abuse.detection_enabled。',
      duration: '封禁时长', thirtyMinutes: '30 分钟', oneDay: '24 小时', permanent: '永久，直到管理员解除',
      reason: '封禁原因', activeOnly: '仅显示有效封禁', empty: '暂无封禁记录',
      automatic: '自动封禁', manual: '手动封禁', blocked: '封禁中', inactive: '已解封或已到期', expires: '到期时间',
      counts: '失败 {failures} 次 · 触发 {strikes} 次',
      blockConfirm: '确认封禁 {ip}，时长为 {duration}？这个 IP 下的所有账号都会受到影响。',
      unblockConfirm: '确认解除 {ip} 的封禁？旧失败计数会被清除，后续试错仍会重新累计。',
      saved: 'IP 封禁已保存', unblocked: 'IP 已解封', failed: 'IP 防护操作失败'
    },
    ipAnomalies: {
      title: '异常检测 / 可疑 IP', detectionStatus: '自动异常检测',
      hint: '同一 IP 跨账号和 Key 累计认证失败，达到阈值后进入列表。可核对来源和最近一次识别的关联用户，再选择封禁或忽略；不会根据试错时填写的账号名封禁用户。',
      status: '处理状态', pending: '待处理', dismissed: '已忽略',
      ipPlaceholder: '单个 IP，留空显示全部', userId: '关联用户 ID（可选）',
      relatedUser: '最近识别的关联用户', unidentified: '未识别身份 / 匿名来源',
      total: '共 {count} 条', empty: '暂无符合条件的可疑 IP',
      counts: '检测时：{shortMinutes} 分钟内失败 ≥{short} 次 · {longHours} 小时内失败 ≥{long} 次',
      firstSeen: '首次发现', lastSeen: '最近检测',
      snapshotHint: '摘要最多每分钟更新一次，页面可见时每 15 秒刷新。次数是保留窗口样本的下界；这里只统计认证失败，正常调用、额度限制和上游错误不列为试错。',
      dismiss: '忽略提醒', dismissConfirm: '忽略 {ip} 的异常提醒？旧失败计数会清空，之后新增试错达到阈值仍会重新提醒。此操作不会解除 IP 封禁。',
      dismissedSuccess: '异常提醒已忽略', suggestedReason: '异常检测：{reason}',
      reasons: {
        invalid_login_input: '登录参数异常 / 扫描试错', invalid_credentials: '账号或密码错误',
        invalid_second_factor: '二次验证码错误', user_inactive: '用户已停用但仍继续请求',
        second_factor_rate_limited: '二次验证多次失败后仍持续尝试', invalid_token: '无效登录令牌试错',
        invalid_auth_rate_limited: '认证试错已限流但仍继续请求',
        api_key_required: '未提供 API Key 的接口试探', invalid_api_key: '无效 API Key 试错',
        api_key_disabled: '已停用的 API Key 继续调用', ip_restricted: '持续触发 Key 的 IP 限制',
        client_ip_blocked: 'IP 已封禁但仍继续请求'
      }
    },
    clearConfirm: {
      title: '清理全部操作日志',
      message: '此操作将永久删除所有操作日志，且不可恢复。清理动作本身会被留痕记录。确定继续吗？',
      totpTitle: '输入二次验证码',
      totpHint: '清理操作日志需要现场验证 TOTP 验证码。',
      success: '已清理 {count} 条操作日志',
      failed: '清理操作日志失败'
    }
  }
}
