export default {
  audit: {
    title: 'Audit Logs',
    description: 'Records management-plane operations by admins and users. Header credentials keep only their first/last characters and request bodies are redacted. Entries cannot be deleted individually; clearing all requires two-factor verification.',
    clearAll: 'Clear All',
    empty: 'No audit logs yet',
    loadFailed: 'Failed to load audit logs',
    filters: {
      all: 'All',
      q: 'Keyword',
      qPlaceholder: 'Path / action / actor email',
      actorEmail: 'Actor Email',
      action: 'Action',
      clientIp: 'Client IP',
      method: 'Method',
      authMethod: 'Auth Method',
      result: 'Result',
      resultSuccess: 'Success',
      resultFailure: 'Failure',
      startTime: 'Start Time',
      endTime: 'End Time'
    },
    columns: {
      time: 'Time',
      actor: 'Actor',
      action: 'Action',
      method: 'Method',
      result: 'Result',
      clientIp: 'Client IP',
      detail: 'Detail'
    },
    detail: {
      title: 'Audit Log Detail',
      actorRole: 'Role',
      methodPath: 'Method / Path',
      latency: 'Latency',
      requestId: 'Request ID',
      peerIp: 'Connection Peer IP',
      clientIpSource: 'IP Resolution Source',
      credential: 'Credential (masked)',
      userAgent: 'User-Agent',
      requestBody: 'Request Body (redacted)',
      extra: 'Extra'
    },
    ipProtection: {
      title: 'IP Blocks', block: 'Block IP', unblock: 'Unblock',
      scopeHint: 'Blocking affects logins and API requests for every account using this IP. Verify the client IP and connection source; older logs may lack trusted source information.',
      autoStatus: 'Automatic blocking',
      rules: 'Anomaly threshold: {short} failures in {shortMinutes} minutes or {long} failures in {longHours} hours',
      penalties: 'First block: {initialMinutes} minutes; repeat block: {repeatHours} hours',
      autoPermanent: 'Permanent block from trigger {count}',
      noAutoPermanent: 'Automatic permanent blocks are disabled; manual permanent blocks remain available',
      configHint: 'Detection lists suspicious IPs for administrator approval by default. Enable security.auth_abuse.enabled for automatic blocking after verifying real client IPs; security.auth_abuse.detection_enabled controls detection.',
      duration: 'Duration', thirtyMinutes: '30 minutes', oneDay: '24 hours', permanent: 'Permanent until unblocked',
      reason: 'Reason', activeOnly: 'Active blocks only', empty: 'No IP blocks',
      automatic: 'Automatic', manual: 'Manual', blocked: 'Blocked', inactive: 'Revoked or expired', expires: 'Expires',
      counts: '{failures} failures · {strikes} triggers',
      blockConfirm: 'Block {ip} for {duration}? Every account using this IP will be affected.',
      unblockConfirm: 'Unblock {ip}? Existing failure counters will be cleared; subsequent failures will accumulate again.',
      saved: 'IP block saved', unblocked: 'IP unblocked', failed: 'IP protection operation failed'
    },
    ipAnomalies: {
      title: 'Anomalies / Suspicious IPs', detectionStatus: 'Automatic anomaly detection',
      hint: 'Authentication failures accumulate across accounts and keys on each IP. Verify the source and last identified user before blocking or dismissing. Account names submitted during guessing are never used to ban users.',
      status: 'Review status', pending: 'Pending review', dismissed: 'Dismissed',
      ipPlaceholder: 'One IP; leave blank for all', userId: 'Related user ID (optional)',
      relatedUser: 'Last identified user', unidentified: 'Unidentified / anonymous source',
      total: '{count} entries', empty: 'No matching suspicious IPs',
      counts: 'At detection: ≥{short} failures in {shortMinutes} minutes · ≥{long} failures in {longHours} hours',
      firstSeen: 'First detected', lastSeen: 'Last detected',
      snapshotHint: 'Summaries update at most once per minute; this list refreshes every 15 seconds while visible. Counts are lower bounds from retained window samples. Normal request frequency, quota limits and upstream errors are excluded.',
      dismiss: 'Dismiss alert', dismissConfirm: 'Dismiss the alert for {ip}? Old failure counters will be cleared; new failures reaching the threshold will alert again. This does not unblock the IP.',
      dismissedSuccess: 'Anomaly alert dismissed', suggestedReason: 'Anomaly detection: {reason}',
      reasons: {
        invalid_login_input: 'Invalid login input / scanning', invalid_credentials: 'Incorrect account or password',
        invalid_second_factor: 'Incorrect second-factor code', user_inactive: 'Disabled user continues requesting',
        second_factor_rate_limited: 'Continued attempts after second-factor lockout', invalid_token: 'Invalid login token attempts',
        invalid_auth_rate_limited: 'Continued requests after authentication abuse rate limiting',
        api_key_required: 'API probing without a key', invalid_api_key: 'Invalid API key attempts',
        api_key_disabled: 'Disabled API key continues requesting', ip_restricted: 'Repeated key IP restriction failures',
        client_ip_blocked: 'Blocked IP continues requesting'
      }
    },
    clearConfirm: {
      title: 'Clear All Audit Logs',
      message: 'This permanently deletes all audit logs and cannot be undone. The clear action itself is recorded. Continue?',
      totpTitle: 'Enter Two-Factor Code',
      totpHint: 'Clearing audit logs requires a fresh TOTP verification.',
      success: 'Cleared {count} audit log(s)',
      failed: 'Failed to clear audit logs'
    }
  }
}
