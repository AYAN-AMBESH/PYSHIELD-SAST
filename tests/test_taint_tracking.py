from pathlib import Path

from sapyscan.scanner import Scanner


def test_injection_rules_require_tainted_data(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
import subprocess

def safe(cursor):
    table = "accounts"
    query = f"SELECT * FROM {table}"
    cursor.execute(query)
    subprocess.run("tar -cvf backup.tar /var/backups", shell=True)

def unsafe(cursor, destination):
    username = input("Username: ")
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
    command = f"tar -cvf backup.tar {destination}"
    subprocess.run(command, shell=True)
""",
        encoding="utf-8",
    )

    findings = Scanner(target).scan()
    assert [finding.rule_id for finding in findings] == [
        "OWASP_A03_2021_CMD",
        "OWASP_A03_2021_SQLI",
    ]


def test_call_graph_tracks_arguments_and_returns(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
def execute_query(cursor, username):
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)

def username_from_request():
    return input("Username: ")

def safe(cursor):
    execute_query(cursor, "admin")

def unsafe(cursor):
    execute_query(cursor, username_from_request())
""",
        encoding="utf-8",
    )

    findings = Scanner(target).scan()
    assert [finding.rule_id for finding in findings] == ["OWASP_A03_2021_SQLI"]
    assert findings[0].assessment == "confirmed"
    assert findings[0].data_flow
    assert any("input(" in step for step in findings[0].data_flow)


def test_call_graph_ignores_safe_arguments(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
def execute_query(cursor, username):
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)

def safe(cursor):
    execute_query(cursor, "admin")
""",
        encoding="utf-8",
    )

    assert Scanner(target).scan() == []


def test_unresolved_parameter_flow_is_marked_for_review(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
def execute_query(cursor, username):
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
""",
        encoding="utf-8",
    )

    findings = Scanner(target).scan()
    assert [finding.rule_id for finding in findings] == ["OWASP_A03_2021_SQLI"]
    assert findings[0].assessment == "needs_review"
    assert findings[0].data_flow
    assert any("parameter" in step for step in findings[0].data_flow)


def test_boolean_fallback_still_traces_taint(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
from flask import request

def lookup_user(cursor):
    username = request.args.get("username") or "guest"
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
""",
        encoding="utf-8",
    )

    findings = Scanner(target).scan()
    assert [finding.rule_id for finding in findings] == ["OWASP_A03_2021_SQLI"]
    assert findings[0].assessment == "confirmed"
    assert any("or operand" in step for step in findings[0].data_flow)


def test_call_graph_resolves_imported_functions_and_methods(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        """
def execute_query(cursor, username):
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
""",
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text(
        """
class QueryService:
    def execute_query(self, cursor, username):
        query = f"SELECT * FROM accounts WHERE username = '{username}'"
        cursor.execute(query)
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
from helpers import execute_query
from service import QueryService

def safe(cursor):
    execute_query(cursor, "admin")
    service = QueryService()
    service.execute_query(cursor, "admin")

def unsafe(cursor):
    execute_query(cursor, input("Username: "))
    service = QueryService()
    service.execute_query(cursor, input("Username: "))
""",
        encoding="utf-8",
    )

    findings = Scanner(tmp_path).scan()
    assert [finding.rule_id for finding in findings] == [
        "OWASP_A03_2021_SQLI",
        "OWASP_A03_2021_SQLI",
    ]


def test_call_graph_ignores_safe_imported_arguments(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        """
def execute_query(cursor, username):
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
from helpers import execute_query

def safe(cursor):
    execute_query(cursor, "admin")
""",
        encoding="utf-8",
    )

    assert Scanner(tmp_path).scan() == []


def test_sanitization_stops_taint(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
import html
import sqlite3

def run(cursor):
    username = input("Username: ")
    safe_username = html.escape(username)
    query = f"SELECT * FROM accounts WHERE username = '{safe_username}'"
    cursor.execute(query)
""",
        encoding="utf-8",
    )

    assert Scanner(target).scan() == []


def test_advanced_taint_tracking(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
import sqlite3

def run_destructuring(cursor):
    user_id, session_id = input("ID: "), "safe"
    query = f"SELECT * FROM accounts WHERE id = '{user_id}'"
    cursor.execute(query)

def run_aug_assign(cursor):
    query = "SELECT * FROM accounts WHERE name = '"
    query += input("Name: ")
    query += "'"
    cursor.execute(query)
""",
        encoding="utf-8",
    )

    findings = Scanner(target).scan()
    assert [finding.rule_id for finding in findings] == [
        "OWASP_A03_2021_SQLI",
        "OWASP_A03_2021_SQLI",
    ]


def test_nested_module_import_resolution(tmp_path: Path) -> None:
    mymodule = tmp_path / "mymodule"
    mymodule.mkdir()
    (mymodule / "__init__.py").write_text("", encoding="utf-8")
    
    (mymodule / "db.py").write_text(
        """
def execute_query(cursor, username):
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
""",
        encoding="utf-8",
    )
    
    (mymodule / "app.py").write_text(
        """
import mymodule.db

def run(cursor):
    mymodule.db.execute_query(cursor, input("Username: "))
""",
        encoding="utf-8",
    )

    findings = Scanner(tmp_path).scan()
    assert len(findings) == 1
    assert findings[0].rule_id == "OWASP_A03_2021_SQLI"


def test_scanner_type_inference(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
import sqlite3

def run_safe_param(cursor, user_id: int):
    query = f"SELECT * FROM accounts WHERE id = {user_id}"
    cursor.execute(query)

def run_unsafe_param(cursor, username: str):
    query = f"SELECT * FROM accounts WHERE name = '{username}'"
    cursor.execute(query)

def run_safe_var(cursor):
    val: int = input("ID: ")
    query = f"SELECT * FROM accounts WHERE id = {val}"
    cursor.execute(query)

def run_unsafe_var(cursor):
    val: str = input("Name: ")
    query = f"SELECT * FROM accounts WHERE name = '{val}'"
    cursor.execute(query)
""",
        encoding="utf-8",
    )
    
    findings = Scanner(target).scan()
    assert len(findings) == 2
    lines = [f.line_no for f in findings]
    assert 10 in lines
    assert 20 in lines




