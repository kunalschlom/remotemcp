from fastmcp import FastMCP


DATABASE_URL ="postgresql://neondb_owner:npg_RPjCGwAZ2Wz5@ep-frosty-frog-a1ectlpt-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"
 
SECRET_KEY = b"super-secret-key"

# --------------------------
# MCP Init
# --------------------------
mcp = FastMCP(name="project remote management")

# --------------------------
# DB Connection (NO POOL)
# --------------------------
async def get_conn():
    import asyncpg
    return await asyncpg.connect(
        DATABASE_URL,
        ssl="require",
    )

@mcp.tool
async def ping():
    return "ok"

# --------------------------
# Token utils
# --------------------------
def create_token(user_id: int):
    import json
    import hmac
    import base64
    import hashlib
    from datetime import datetime,timedelta
    payload = {
        "user_id": user_id,
        "exp": (datetime.utcnow() + timedelta(hours=2)).timestamp(),
    }
    payload_bytes = json.dumps(payload).encode()
    sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload_bytes + b"." + sig).decode()

def verify_token(token: str):
    import base64
    import hmac
    import json
    import hashlib
    from datetime import datetime

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
# @mcp.tool
# async def register(email: str, password: str):
#     import bcrypt
#     hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
#     conn = await get_conn()

#     try:
#         await conn.execute(
#             "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
#             email,
#             hashed,
#         )
#     except Exception:
#         return {"message": "User already exists"}
#     finally:
#         await conn.close()

#     return {"message": "User registered successfully"}

# --------------------------
# Auth: Login
# --------------------------
# @mcp.tool
# async def login(email: str, password: str):
#     import bcrypt
#     conn = await get_conn()

#     row = await conn.fetchrow(
#         "SELECT id, password_hash FROM users WHERE email=$1",
#         email,
#     )

#     await conn.close()

#     if not row:
#         return {"message": "Invalid credentials"}

#     if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
#         return {"message": "Invalid credentials"}

#     return {"token": create_token(row["id"])}

# # --------------------------
# # Add Task
# # --------------------------
# @mcp.tool
# async def add_task(
#     token: str,
#     task_name: str,
#     due_date: str = None,
#     priority: str = None,
# ):
#     from datetime import datetime
#     user_id = require_user(token)
#     conn = await get_conn()

#     due = datetime.strptime(due_date, "%Y-%m-%d").date() if due_date else None

#     await conn.execute(
#         """
#         INSERT INTO tasks (user_id, task_name, due_date, priority, status)
#         VALUES ($1, $2, $3, $4, 'pending')
#         """,
#         user_id,
#         task_name,
#         due,
#         priority,
#     )

#     await conn.close()
#     return {"message": "Task added"}

# # --------------------------
# # List Tasks
# # --------------------------
# @mcp.tool
# async def list_tasks(token: str, filters: dict = {}):
#     from datetime import datetime
#     user_id = require_user(token)
#     conn = await get_conn()

#     conditions = ["user_id=$1"]
#     values = [user_id]

#     for key in ["priority", "status"]:
#         if key in filters:
#             conditions.append(f"{key}=${len(values)+1}")
#             values.append(filters[key])

#     if "due_date" in filters:
#         conditions.append(f"due_date=${len(values)+1}")
#         values.append(datetime.strptime(filters["due_date"], "%Y-%m-%d").date())

#     if "keyword" in filters:
#         conditions.append(f"task_name ILIKE ${len(values)+1}")
#         values.append(f"%{filters['keyword']}%")

#     sql = "SELECT * FROM tasks WHERE " + " AND ".join(conditions)
#     rows = await conn.fetch(sql, *values)

#     await conn.close()
#     return {"rows": [dict(r) for r in rows]}

# # --------------------------
# # Task Summary
# # --------------------------
# @mcp.tool
# async def task_summary(token: str, filters: dict = {}):
#     from datetime import datetime
#     user_id = require_user(token)
#     conn = await get_conn()

#     rows = await conn.fetch(
#         "SELECT status, due_date FROM tasks WHERE user_id=$1",
#         user_id,
#     )

#     await conn.close()

#     today = datetime.today().date()
#     pending = completed = overdue = 0

#     for r in rows:
#         if r["status"] == "pending":
#             pending += 1
#             if r["due_date"] and r["due_date"] < today:
#                 overdue += 1
#         elif r["status"] == "completed":
#             completed += 1

#     return {
#         "total": len(rows),
#         "pending": pending,
#         "completed": completed,
#         "overdue": overdue,
#     }

# # --------------------------
# # Complete Task
# # --------------------------
# @mcp.tool
# async def complete_task(token: str, task_id: int):
#     user_id = require_user(token)
#     conn = await get_conn()

#     result = await conn.execute(
#         """
#         UPDATE tasks SET status='completed'
#         WHERE task_id=$1 AND user_id=$2
#         """,
#         task_id,
#         user_id,
#     )

#     await conn.close()

#     if result.endswith("0"):
#         return {"message": "No task found"}

#     return {"message": "Task completed"}

# # --------------------------
# # Update Task
# # --------------------------
# @mcp.tool
# async def update_task(
#     token: str,
#     task_id: int,
#     name: str = None,
#     due_date: str = None,
#     priority: str = None,
#     status: str = None,
# ):
#     from datetime import datetime 
#     user_id = require_user(token)
#     conn = await get_conn()

#     updates = []
#     values = []

#     if name:
#         updates.append(f"task_name=${len(values)+1}")
#         values.append(name)
#     if due_date:
#         updates.append(f"due_date=${len(values)+1}")
#         values.append(datetime.strptime(due_date, "%Y-%m-%d").date())
#     if priority:
#         updates.append(f"priority=${len(values)+1}")
#         values.append(priority)
#     if status:
#         updates.append(f"status=${len(values)+1}")
#         values.append(status)

#     if not updates:
#         await conn.close()
#         return {"message": "Nothing to update"}

#     sql = f"""
#         UPDATE tasks SET {', '.join(updates)}
#         WHERE task_id=${len(values)+1} AND user_id=${len(values)+2}
#     """

#     values.extend([task_id, user_id])
#     result = await conn.execute(sql, *values)

#     await conn.close()

#     if result.endswith("0"):
#         return {"message": "No task found"}

#     return {"message": "Task updated"}

# # --------------------------
# # Delete Task
# # --------------------------
# @mcp.tool
# async def delete_task(token: str, task_id: int):
#     user_id = require_user(token)
#     conn = await get_conn()

#     result = await conn.execute(
#         "DELETE FROM tasks WHERE task_id=$1 AND user_id=$2",
#         task_id,
#         user_id,
#     )

#     await conn.close()

#     if result.endswith("0"):
#         return {"message": "No task found"}

#     return {"message": "Task deleted"}

# # --------------------------
# Test Tool
# --------------------------
# @mcp.tool
# async def test_tool(number: int):
#     return number

# --------------------------
# Run Server
# --------------------------
if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8000)
