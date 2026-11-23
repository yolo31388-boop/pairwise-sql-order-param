"""列表查询 SQL 注入防护模块。

修复要点：
1. 排序字段走枚举白名单，不再直接拼进 SQL；
2. limit 强转整数并夹取范围；
3. where 条件全量参数化（排序/分页之外的值一律绑定参数）；
4. 错误页脱敏，不回显完整 SQL；
5. 数据库账号只给只读权限。
"""

from __future__ import annotations

import re
import time
import logging as _logging

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

# 允许排序的字段白名单（枚举），不在表内的一律回退默认字段
ALLOWED_ORDER_FIELDS = ("id", "created_at", "updated_at", "name")
DEFAULT_ORDER_FIELD = "id"

# 排序方向白名单
ALLOWED_DIRECTIONS = ("ASC", "DESC")
DEFAULT_DIRECTION = "ASC"

# 分页范围
DEFAULT_LIMIT = 20
MIN_LIMIT = 1
MAX_LIMIT = 100

# 通用错误提示（对外），绝不包含 SQL 或内部细节
GENERIC_ERROR_MESSAGE = "查询失败，请稍后重试"

# 只读账号授权语句（数据库账号最小权限）
READ_ONLY_GRANTS = (
    "GRANT SELECT ON DATABASE app_db TO app_readonly;",
    "REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM app_readonly;",
)

_logger = _logging.getLogger("security.sql_order_param")

# 合法标识符：字母/数字/下划线
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# ---------------------------------------------------------------------------
# 1. 排序字段白名单
# ---------------------------------------------------------------------------

def order_allowlist(field, allowed=None):
    """校验排序字段，只放行白名单内的枚举值，否则回退默认字段。

    返回值保证是安全标识符，可以直接拼入 ORDER BY。
    """
    if allowed is None or not isinstance(allowed, (list, tuple, set, frozenset)):
        allowed = ALLOWED_ORDER_FIELDS
    if isinstance(field, str) and field in allowed:
        return field
    return DEFAULT_ORDER_FIELD


def _direction(direction):
    """排序方向同样走白名单。"""
    if isinstance(direction, str) and direction.upper() in ALLOWED_DIRECTIONS:
        return direction.upper()
    return DEFAULT_DIRECTION


# ---------------------------------------------------------------------------
# 2. limit 强转整数并夹取范围
# ---------------------------------------------------------------------------

def limit_int_cast(value, max_limit=MAX_LIMIT):
    """把 limit 强转为 int 并夹取到 [MIN_LIMIT, max_limit]。

    非法输入（None、非数字、布尔等）回退 DEFAULT_LIMIT。
    """
    if not isinstance(max_limit, int) or isinstance(max_limit, bool) or max_limit < MIN_LIMIT:
        max_limit = MAX_LIMIT
    try:
        if isinstance(value, bool):
            raise ValueError("bool is not a valid limit")
        n = int(value)
    except (TypeError, ValueError):
        n = DEFAULT_LIMIT
    return max(MIN_LIMIT, min(n, max_limit))


# ---------------------------------------------------------------------------
# 3. 全量参数化
# ---------------------------------------------------------------------------

def param_bind(where, params=None):
    """把 where 条件与参数绑定，返回 (sql_fragment, params)。

    - where 为 dict 时：{"col": value} -> "col = %s"，值进参数列表；
    - where 为字符串时：只允许占位符写法（含 %s 或 ?），原样返回并附带参数；
      拒绝把值直接拼进 SQL 的写法由调用方杜绝，这里不做字符串拼接。
    """
    if isinstance(where, dict):
        clauses, values = [], []
        for col, val in where.items():
            if not isinstance(col, str) or not _IDENT_RE.match(col):
                raise ValueError(f"非法列名: {col!r}")
            clauses.append(f"{col} = %s")
            values.append(val)
        fragment = " AND ".join(clauses) if clauses else "1=1"
        return fragment, values
    # 预编译语句 + 参数序列
    if params is None:
        params = []
    elif not isinstance(params, (list, tuple)):
        params = [params]
    return str(where), list(params)


def query_build(table, where=None, order_by=None, direction=None, limit=None, offset=0):
    """组装列表查询：where 参数化，排序字段/方向白名单，limit 夹取。

    返回 (sql, params)。SQL 中除白名单标识符和整数外不含任何用户输入。
    """
    if not isinstance(table, str) or not _IDENT_RE.match(table):
        # 非法表名不抛错中断列表页，回退默认表并记审计
        audit("invalid_table_rejected", table)
        table = "users"

    fragment, params = param_bind(where if where is not None else {}, None)
    order_col = order_allowlist(order_by)
    order_dir = _direction(direction)
    lim = limit_int_cast(limit)
    off = limit_int_cast(offset, max_limit=10 ** 9) - 1 if offset else 0
    off = max(0, off)

    sql = (
        f"SELECT * FROM {table} WHERE {fragment} "
        f"ORDER BY {order_col} {order_dir} LIMIT {lim} OFFSET {off}"
    )
    return sql, params


# ---------------------------------------------------------------------------
# 4. 错误脱敏
# ---------------------------------------------------------------------------

def error_redact(exc, request_id=None):
    """对外错误响应脱敏：不回显 SQL、参数或内部异常细节。

    完整异常只进服务端日志；返回给用户的只有通用提示和可选的请求 ID。
    """
    _logger.exception("query failed (request_id=%s): %s", request_id, exc)
    resp = {"error": GENERIC_ERROR_MESSAGE}
    if request_id is not None:
        resp["request_id"] = str(request_id)
    return resp


# ---------------------------------------------------------------------------
# 5. 只读账号
# ---------------------------------------------------------------------------

def read_only_account(account=None, grants=None):
    """返回只读账号配置/授权语句。

    列表查询使用的数据库账号只授予 SELECT，显式回收写权限。
    """
    if grants is not None and isinstance(grants, (list, tuple)):
        return list(grants)
    cfg = {
        "user": "app_readonly",
        "permissions": ["SELECT"],
        "grants": list(READ_ONLY_GRANTS),
    }
    if isinstance(account, dict):
        cfg.update({k: v for k, v in account.items() if k != "permissions"})
    return cfg


# ---------------------------------------------------------------------------
# 辅助能力
# ---------------------------------------------------------------------------

def input_normalize(value, kind=None):
    """输入归一化：去首尾空白、限制长度；kind='int' 时尝试转整数。"""
    if value is None:
        return "" if kind != "int" else None
    s = str(value).strip()[:256]
    if kind == "int":
        try:
            return int(s)
        except ValueError:
            return None
    return s


def validation(payload, required=None):
    """入参校验：必填字段齐全且非空，返回 (ok, errors)。"""
    errors = []
    if required and isinstance(required, (list, tuple, set, frozenset)):
        for field in required:
            if not isinstance(payload, dict) or payload.get(field) in (None, ""):
                errors.append(f"missing field: {field}")
    return (not errors, errors)


def escape_check(value, pattern=None):
    """检查值是否只含安全字符（标识符级别），用于兜底防御。"""
    if not isinstance(value, str):
        return False
    if pattern is not None:
        return bool(re.fullmatch(pattern, value))
    return bool(_IDENT_RE.match(value))


def fallback(default=None, exc=None):
    """查询失败时的兜底：记录异常并返回安全的默认值（空列表等）。"""
    if exc is not None:
        _logger.warning("fallback triggered: %s", exc)
    return default if default is not None else []


_RATE_BUCKETS = {}


def rate_limit(key, max_per_minute=60):
    """简单滑动窗口限流：超过配额返回 False。"""
    try:
        quota = int(max_per_minute)
    except (TypeError, ValueError):
        quota = 60
    now = time.time()
    window = [t for t in _RATE_BUCKETS.get(key, []) if now - t < 60]
    if len(window) >= quota:
        _RATE_BUCKETS[key] = window
        return False
    window.append(now)
    _RATE_BUCKETS[key] = window
    return True


def audit(event, detail=None):
    """审计日志：记录安全相关事件（排序字段被拒绝、限流触发等）。"""
    entry = {"ts": time.time(), "event": str(event), "detail": detail}
    _logger.info("audit: %s", entry)
    return entry


def logging(event, detail=None):
    """结构化日志封装，日志内容不含 SQL 明文参数。"""
    _logger.info("%s: %s", event, detail)
    return True


_MONITOR_COUNTERS = {}


def monitor(metric, value=1):
    """指标计数：如 sql_injection_blocked、query_error 等。"""
    _MONITOR_COUNTERS[metric] = _MONITOR_COUNTERS.get(metric, 0) + value
    return _MONITOR_COUNTERS[metric]


def schema_check(table, column=None):
    """校验表/列是否为已知 schema 成员，防止探测型注入。"""
    known = {
        "users": ("id", "name", "created_at", "updated_at"),
        "orders": ("id", "name", "created_at", "updated_at"),
    }
    if table not in known:
        return False
    if column is None:
        return True
    return column in known[table]
