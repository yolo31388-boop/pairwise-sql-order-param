import pytest
import security.sql_order_param as mod

CASES = [
    ("order_allowlist", (1, 2)),
    ("limit_int_cast", (1, 2)),
    ("param_bind", (1, 2)),
    ("error_redact", (1, 2)),
    ("read_only_account", (1, 2)),
    ("input_normalize", (1, 2)),
    ("query_build", (1, 2)),
    ("validation", (1, 2)),
    ("audit", (1, 2)),
    ("rate_limit", (1, 2)),
    ("escape_check", (1, 2)),
    ("fallback", (1, 2)),
    ("logging", (1, 2)),
    ("monitor", (1, 2)),
    ("schema_check", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
