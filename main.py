
from fastmcp import FastMCP
import asyncpg
import psycopg2
from datetime import datetime, timedelta
import bcrypt
import hmac
import hashlib
import base64
import json


# Initialize MCP
mcp = FastMCP(name="project remote management")

# SECRET for token signing
SECRET_KEY = b"super-secret-key"

# --------------------------
# Utility: Token handling
# --------------------------
def create_token(user_id: int):
    payload = {
        "user_id": user_id,
        "exp": (datetime.utcnow() + timedelta(hours=2)).timestamp()
    }
    payload_bytes = json.dumps(payload).encode()
    sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload_bytes + b"." + sig).decode()
    return token


def verify_token(token: str):
    try:
        decoded = base64.urlsafe_b64decode(token.encode())
        payload_bytes, sig = decoded.rsplit(b".", 1)

        expected_sig = hmac.new(
            SECRET_KEY, payload_bytes, hashlib.sha256
        ).digest()

        if not hmac.compare_digest(sig, expected_sig):
            return None

        payload = json.loads(payload_bytes)
        if payload["exp"] < datetime.utcnow().timestamp():
            return None

        return payload["user_id"]
    except Exception:
        return None


def require_user(token: str):
    user_id = verify_token(token)
    if not user_id:
        raise Exception("Invalid or expired token")
    return user_id


# --------------------------
# Database Initialization
# --------------------------
def initialise_db():
    conn = psycopg2.connect(
        host="localhost",
        port=5432,
        user="postgres",
        password="kunal",
        database="projectmanagement"
    )
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            task_id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            task_name TEXT NOT NULL,
            due_date DATE,
            priority TEXT,
            status TEXT DEFAULT 'pending'
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


# --------------------------
# Auth: Register
# --------------------------
@mcp.tool
async def register(email: str, password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    conn = await asyncpg.connect(
        host="localhost", port=5432,
        user="postgres", password="kunal",
        database="projectmanagement"
    )

    try:
        await conn.execute(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
            email, hashed
        )
    except Exception:
        await conn.close()
        return {"message": "User already exists"}

    await conn.close()
    return {"message": "User registered successfully"}


# --------------------------
# Auth: Login
# --------------------------
@mcp.tool
async def login(email: str, password: str):
    conn = await asyncpg.connect(
        host="localhost", port=5432,
        user="postgres", password="kunal",
        database="projectmanagement"
    )

    row = await conn.fetchrow(
        "SELECT id, password_hash FROM users WHERE email=$1", email
    )
    await conn.close()

    if not row:
        return {"message": "Invalid credentials"}

    if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return {"message": "Invalid credentials"}

    token = create_token(row["id"])
    return {"token": token}


# --------------------------
# Add Task
# --------------------------
@mcp.tool
async def add_task(token: str, task_name: str, due_date: str = None, priority: str = None):
    user_id = require_user(token)

    due_date_obj = None
    if due_date:
        due_date_obj = datetime.strptime(due_date, "%Y-%m-%d").date()

    conn = await asyncpg.connect(
        host="localhost", port=5432,
        user="postgres", password="kunal",
        database="projectmanagement"
    )

    await conn.execute(
        """
        INSERT INTO tasks (user_id, task_name, due_date, priority, status)
        VALUES ($1, $2, $3, $4, 'pending')
        """,
        user_id, task_name, due_date_obj, priority
    )

    await conn.close()
    return {"message": "Task added"}





@mcp.tool
async def list_tasks(token:str,filters: dict = {}):
    user_id = require_user(token) 
    conditions = ["user_id=$1"]
    values = [user_id]

    if "priority" in filters:
        conditions.append(f"priority=${len(values)+1}")
        values.append(filters["priority"])

    if "status" in filters:
        conditions.append(f"status=${len(values)+1}")
        values.append(filters["status"])

    if "due_date" in filters:
        due_date = datetime.strptime(filters["due_date"], "%Y-%m-%d").date()
        conditions.append(f"due_date=${len(values)+1}")
        values.append(due_date)

    if "due_date_start" in filters:
        start = datetime.strptime(filters["due_date_start"], "%Y-%m-%d").date()
        conditions.append(f"due_date>=${len(values)+1}")
        values.append(start)

    if "due_date_end" in filters:
        end = datetime.strptime(filters["due_date_end"], "%Y-%m-%d").date()
        conditions.append(f"due_date<=${len(values)+1}")
        values.append(end)

    if "keyword" in filters:
        conditions.append(f"task_name LIKE ${len(values)+1}")
        values.append(f"%{filters['keyword']}%")

    sql = "SELECT * FROM tasks WHERE " + " AND ".join(conditions)

    conn = await asyncpg.connect(
        host="localhost",
        port=5432,
        user="postgres",
        password="kunal",
        database="projectmanagement"
    )

    rows = await conn.fetch(sql, *values)
    await conn.close()

    return {
        "message": "Tasks fetched successfully.",
        "rows": [dict(row) for row in rows]
    }


##Summarize tasks

async def list_tasks2(token:str,filters: dict = {}):
    user_id = require_user(token)
    conditions = ["user_id=$1"]
    values = [user_id]

    if "priority" in filters:
        conditions.append(f"priority=${len(values)+1}")
        values.append(filters["priority"])

    if "status" in filters:
        conditions.append(f"status=${len(values)+1}")
        values.append(filters["status"])

    if "due_date" in filters:
        due_date = datetime.strptime(filters["due_date"], "%Y-%m-%d").date()
        conditions.append(f"due_date=${len(values)+1}")
        values.append(due_date)

    if "due_date_start" in filters:
        start = datetime.strptime(filters["due_date_start"], "%Y-%m-%d").date()
        conditions.append(f"due_date>=${len(values)+1}")
        values.append(start)

    if "due_date_end" in filters:
        end = datetime.strptime(filters["due_date_end"], "%Y-%m-%d").date()
        conditions.append(f"due_date<=${len(values)+1}")
        values.append(end)

    if "keyword" in filters:
        conditions.append(f"task_name LIKE ${len(values)+1}")
        values.append(f"%{filters['keyword']}%")

    sql = "SELECT * FROM tasks WHERE " + " AND ".join(conditions)

    conn = await asyncpg.connect(
        host="localhost",
        port=5432,
        user="postgres",
        password="kunal",
        database="projectmanagement"
    )

    rows = await conn.fetch(sql, *values)
    await conn.close()

    return {
        "message": "Tasks fetched successfully.",
        "rows": [dict(row) for row in rows]
    }


@mcp.tool
async def task_summary(token:str,filters: dict = {}):
    """
    Return a summary of tasks, including total, pending, completed, overdue.
    Optional filters: priority, status, due_date
    """
    result = await list_tasks2(token,filters)
    rows = result.get('rows', [])

    total = len(rows)
    pending = 0
    completed = 0
    overdue = 0
    today = datetime.today().date()

    for row in rows:
        due_date = row['due_date']  # access dict key
        status = row['status']

        if status == 'pending':
            pending += 1
            if due_date:
                if isinstance(due_date, str):
                    # If somehow a string, convert to date
                    try:
                        due_date = datetime.strptime(due_date, "%Y-%m-%d").date()
                    except ValueError:
                        continue
                if due_date < today:
                    overdue += 1
        elif status == 'completed':
            completed += 1

    return {
        "total": total,
        "pending": pending,
        "completed": completed,
        "overdue": overdue
    }
# --------------------------
# Complete Task
# --------------------------
@mcp.tool
async def complete_task(token:str,name: str, date: str = None):
    user_id = require_user(token)
    if date:
        due_date = datetime.strptime(date, "%Y-%m-%d").date()
        sql = """
            UPDATE tasks
            SET status='completed'
            WHERE task_name=$1 AND due_date=$2 AND user_id=$3
        """
        params = [name, due_date, user_id]
    else:
        sql = """
            UPDATE tasks
            SET status='completed'
            WHERE task_name=$1 AND user_id=$2
        """
        params = [name, user_id]

    conn = await asyncpg.connect(
        host="localhost",
        port=5432,
        user="postgres",
        password="kunal",
        database="projectmanagement"
    )

    result = await conn.execute(sql, *params)
    await conn.close()

    if int(result.split()[-1]) == 0:
        return {"message": "No task found to update."}

    return {"message": "Task successfully marked as completed."}


# --------------------------
# Update Task
# --------------------------
@mcp.tool
async def update_task(token:str,task_id: int, name: str = None, due_date: str = None,
                      priority: str = None, status: str = None):
    user_id = require_user(token)
    updates = []
    values = []

    if name:
        updates.append(f"task_name=${len(values)+1}")
        values.append(name)

    if due_date:
        due = datetime.strptime(due_date, "%Y-%m-%d").date()
        updates.append(f"due_date=${len(values)+1}")
        values.append(due)

    if priority:
        updates.append(f"priority=${len(values)+1}")
        values.append(priority)

    if status:
        updates.append(f"status=${len(values)+1}")
        values.append(status)

    if not updates:
        return {"message": "Nothing to update."}

    sql = f"""
        UPDATE tasks
        SET {', '.join(updates)}
        WHERE task_id=${len(values)+1} AND user_id=${len(values)+2}
    """
    values.extend([task_id, user_id])

    conn = await asyncpg.connect(
        host="localhost",
        port=5432,
        user="postgres",
        password="kunal",
        database="projectmanagement"
    )

    result = await conn.execute(sql, *values)
    await conn.close()

    if int(result.split()[-1]) == 0:
        return {"message": "No task found to update."}

    return {"message": "Task updated successfully."}


# --------------------------
# Delete Task
# --------------------------
@mcp.tool
async def delete_task(token:str,task_id: int):
    user_id = require_user(token)
    conn = await asyncpg.connect(
        host="localhost",
        port=5432,
        user="postgres",
        password="kunal",
        database="projectmanagement"
    )

    result = await conn.execute(
        "DELETE FROM tasks WHERE task_id=$1 AND user_id=$2",
        task_id, user_id
    )

    await conn.close()

    if int(result.split()[-1]) == 0:
        return {"message": "No task found to delete."}

    return {"message": "Task deleted successfully."}

# --------------------------
# Run
# --------------------------
    

initialise_db()
if __name__ == "__main__":
    

    mcp.run(transport='http',host='0.0.0.0',port=8000)
