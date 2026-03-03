"""
db_inspector.py
Provides schema browsing, paginated row access, and a read-only SQL console
for the Database Inspector page.
All queries use parameterised statements.
Destructive statements (DELETE, INSERT, UPDATE, DROP, ALTER) are blocked.
"""

import re
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'nmids.db')

BLOCKED_KEYWORDS = re.compile(
    r'\b(DELETE|INSERT|UPDATE|DROP|ALTER|CREATE|REPLACE|TRUNCATE|ATTACH|DETACH)\b',
    re.IGNORECASE
)

ALLOWED_STATEMENT = re.compile(
    r'^\s*(SELECT|PRAGMA|EXPLAIN|WITH)\b',
    re.IGNORECASE
)

TABLES = ['traffic_log', 'alerts', 'baseline']


def _conn(read_only=False):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if read_only:
        conn.execute("PRAGMA query_only = ON")
    return conn


# ─── Schema browser ───────────────────────────────────────────────────────────

def get_schema() -> dict:
    """
    Return column info and index list for all 3 tables.
    """
    conn   = _conn()
    schema = {}
    for table in TABLES:
        cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
        idxs = conn.execute(f"PRAGMA index_list({table})").fetchall()
        idx_detail = []
        for idx in idxs:
            info = conn.execute(f"PRAGMA index_info({idx['name']})").fetchall()
            idx_detail.append({
                "name":    idx['name'],
                "unique":  bool(idx['unique']),
                "columns": [i['name'] for i in info]
            })
        schema[table] = {
            "columns": [dict(c) for c in cols],
            "indexes": idx_detail,
        }
    conn.close()
    return schema


# ─── Paginated row browser ────────────────────────────────────────────────────

def get_table_rows(table: str, page: int = 1, per_page: int = 25,
                   filter_col: str = None, filter_val: str = None,
                   sort_col: str = 'id', sort_dir: str = 'DESC') -> dict:
    """
    Return a page of rows from the named table.
    per_page must be 25, 50, or 100.
    Only whitelisted table names and sort columns accepted.
    """
    if table not in TABLES:
        return {"error": "Unknown table", "rows": [], "total": 0}
    per_page = per_page if per_page in (25, 50, 100) else 25
    page     = max(1, int(page))
    offset   = (page - 1) * per_page

    # Build column whitelist dynamically
    conn  = _conn()
    cols  = [r['name'] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if sort_col not in cols:
        sort_col = 'id'
    sort_dir = 'DESC' if sort_dir.upper() == 'DESC' else 'ASC'

    where_clause = ""
    params       = []
    if filter_col and filter_col in cols and filter_val:
        where_clause = f"WHERE {filter_col} LIKE ?"
        params.append(f"%{filter_val}%")

    count_sql = f"SELECT COUNT(*) FROM {table} {where_clause}"
    total     = conn.execute(count_sql, params).fetchone()[0]

    data_sql  = (f"SELECT * FROM {table} {where_clause} "
                 f"ORDER BY {sort_col} {sort_dir} LIMIT ? OFFSET ?")
    rows      = conn.execute(data_sql, params + [per_page, offset]).fetchall()
    conn.close()

    return {
        "table":    table,
        "columns":  cols,
        "rows":     [dict(r) for r in rows],
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, (total + per_page - 1) // per_page),
    }


# ─── Read-only SQL console ────────────────────────────────────────────────────

def run_query(sql: str) -> dict:
    """
    Execute a user-supplied SQL statement with safety checks.
    Only SELECT, PRAGMA, EXPLAIN and WITH queries are permitted.
    PRAGMA query_only=ON is enforced at connection level.
    """
    sql = sql.strip()

    if not sql:
        return {"error": "Empty query", "rows": [], "columns": []}

    if BLOCKED_KEYWORDS.search(sql):
        return {"error": "Blocked: destructive statements are not permitted.", "rows": [], "columns": []}

    if not ALLOWED_STATEMENT.match(sql):
        return {"error": "Only SELECT, PRAGMA, EXPLAIN, and WITH queries are allowed.", "rows": [], "columns": []}

    try:
        conn = _conn(read_only=True)
        cur  = conn.execute(sql)
        rows = cur.fetchmany(500)        # cap result set
        cols = [d[0] for d in cur.description] if cur.description else []
        conn.close()
        return {
            "columns": cols,
            "rows":    [list(r) for r in rows],
            "count":   len(rows),
        }
    except sqlite3.Error as e:
        return {"error": str(e), "rows": [], "columns": []}


# ─── Table statistics ─────────────────────────────────────────────────────────

def get_table_counts() -> dict:
    conn   = _conn()
    result = {}
    for table in TABLES:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
        result[table] = row['n']
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    page_size  = conn.execute("PRAGMA page_size").fetchone()[0]
    result['db_size_bytes'] = page_count * page_size
    conn.close()
    return result
