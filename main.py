from fastmcp import FastMCP
import asyncpg
from datetime import datetime, timedelta
import bcrypt
import hmac
import hashlib
import base64
import json
from dotenv import load_dotenv
import os
import asyncio

# --------------------------
# Load env
# --------------------------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key").encode()

# --------------------------
# MCP Init
# --------------------------
mcp = FastMCP(name="project remote management")

# --------------------------
# DB Pool (GLOBAL)
# --------------------------
pool: asyncpg.Pool | None = None


async def init_db():
    global pool
    pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=5,
        ssl="require",
    )


# --------------------------
# Token utils
# --------------------------
def create_token(user_id: int):
    payload = {
        "user_id": user_id,
        "exp": (datetime.utcnow() + timedelta(hours=2)).timestamp(),
    }
    payload_bytes = json.dumps(payload).encode()
    sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload_bytes + b"." + sig).decode()


def verify_token(token: str):
    try:
        decoded = base64.urlsafe_b64decode(token.encode())
        payload_bytes, sig = decoded.rsplit(b".", 1)

        expected = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None

        payload = json.loads(payload_bytes)
        if payload["exp"] < datetime.utcnow().timestamp():
            return None

        return payload["user_id"]
    except Exception:
        return None


def require_user(token: str):
    uid = verify_token(token)
    if not uid:
        raise Exception("Invalid or expired token")
    return uid


# --------------------------
# Auth: Register
# --------------------------
@mcp.tool
async def register(email: str, password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    async with pool.acquire() as conn:
        try:
            await conn.execute(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
                email,
                hashed,
            )
        except Exception:
            return {"message": "User already exists"}

    return {"message": "User registered successfully"}


# --------------------------
# Auth: Login
# --------------------------
@mcp.tool
async def login(email: str, password: str):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, password_hash FROM users WHERE email=$1", email
        )

    if not row:
        return {"message": "Invalid credentials"}

    if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return {"message": "Invalid credentials"}

    return {"token": create_token(row["id"])}


# --------------------------
# Add Task
# --------------------------
@mcp.tool
async def add_task(token: str, task_name: str, due_date: str = None, priority: str = None):
    user_id = require_user(token)
    due = datetime.strptime(due_date, "%Y-%m-%d").date() if due_date else None

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO tasks (user_id, task_name, due_date, priority, status)
            VALUES ($1, $2, $3, $4, 'pending')
            """,
            user_id,
            task_name,
            due,
            priority,
        )

    return {"message": "Task added"}


# --------------------------
# List Tasks (internal)
# --------------------------
async def _list_tasks(user_id: int, filters: dict):
    conditions = ["user_id=$1"]
    values = [user_id]

    for key in ["priority", "status"]:
        if key in filters:
            conditions.append(f"{key}=${len(values)+1}")
            values.append(filters[key])

    if "due_date" in filters:
        conditions.append(f"due_date=${len(values)+1}")
        values.append(datetime.strptime(filters["due_date"], "%Y-%m-%d").date())

    if "keyword" in filters:
        conditions.append(f"task_name ILIKE ${len(values)+1}")
        values.append(f"%{filters['keyword']}%")

    sql = "SELECT * FROM tasks WHERE " + " AND ".join(conditions)

    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *values)

    return [dict(r) for r in rows]


# --------------------------
# List Tasks
# --------------------------
@mcp.tool
async def list_tasks(token: str, filters: dict = {}):
    user_id = require_user(token)
    rows = await _list_tasks(user_id, filters)
    return {"rows": rows}


# --------------------------
# Task Summary
# --------------------------
@mcp.tool
async def task_summary(token: str, filters: dict = {}):
    user_id = require_user(token)
    rows = await _list_tasks(user_id, filters)

    today = datetime.today().date()
    pending = completed = overdue = 0

    for r in rows:
        if r["status"] == "pending":
            pending += 1
            if r["due_date"] and r["due_date"] < today:
                overdue += 1
        elif r["status"] == "completed":
            completed += 1

    return {
        "total": len(rows),
        "pending": pending,
        "completed": completed,
        "overdue": overdue,
    }


# --------------------------
# Complete Task
# --------------------------
@mcp.tool
async def complete_task(token: str, task_id: int):
    user_id = require_user(token)

    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE tasks SET status='completed'
            WHERE task_id=$1 AND user_id=$2
            """,
            task_id,
            user_id,
        )

    if result.endswith("0"):
        return {"message": "No task found"}

    return {"message": "Task completed"}


# --------------------------
# Update Task
# --------------------------
@mcp.tool
async def update_task(
    token: str,
    task_id: int,
    name: str = None,
    due_date: str = None,
    priority: str = None,
    status: str = None,
):
    user_id = require_user(token)
    updates, values = [], []

    if name:
        updates.append(f"task_name=${len(values)+1}")
        values.append(name)
    if due_date:
        updates.append(f"due_date=${len(values)+1}")
        values.append(datetime.strptime(due_date, "%Y-%m-%d").date())
    if priority:
        updates.append(f"priority=${len(values)+1}")
        values.append(priority)
    if status:
        updates.append(f"status=${len(values)+1}")
        values.append(status)

    if not updates:
        return {"message": "Nothing to update"}

    sql = f"""
        UPDATE tasks SET {', '.join(updates)}
        WHERE task_id=${len(values)+1} AND user_id=${len(values)+2}
    """
    values.extend([task_id, user_id])

    async with pool.acquire() as conn:
        result = await conn.execute(sql, *values)

    if result.endswith("0"):
        return {"message": "No task found"}

    return {"message": "Task updated"}


# --------------------------
# Delete Task
# --------------------------
@mcp.tool
async def delete_task(token: str, task_id: int):
    user_id = require_user(token)

    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM tasks WHERE task_id=$1 AND user_id=$2",
            task_id,
            user_id,
        )

    if result.endswith("0"):
        return {"message": "No task found"}

    return {"message": "Task deleted"}


# --------------------------
# Test Tool
# --------------------------
@mcp.tool
async def test_tool(number: int):
    return number


# --------------------------
# Run Server
# --------------------------
async def main():
    await init_db()
    mcp.run(transport="http", host="0.0.0.0", port=8000, debug=True)


if __name__ == "__main__":
    asyncio.run(main())
