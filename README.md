# pairwise-sql-order-param

## 领域

安全

## 主题

SQL 排序注入

## 说明

排序白名单、limit 夹取与只读账号。

初始状态下 `security/sql_order_param.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
