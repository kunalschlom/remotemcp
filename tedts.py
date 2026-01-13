import asyncpg
import asyncio
import os
from dotenv import load_dotenv

# Load env vars
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

async def test_connection():
    print("Connecting to Neon...")

    pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=1,
        ssl="require",
    )

    async with pool.acquire() as conn:
        result = await conn.fetchval("SELECT 1;")
        print("Connection OK, result:", result)

    await pool.close()
    print("Pool closed cleanly.")

if __name__ == "__main__":
    asyncio.run(test_connection())
