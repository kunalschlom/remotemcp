from dotenv import load_dotenv
import os
import asyncpg
import asyncio

load_dotenv()

async def test_connection():
    try:
        print("Attempting to connect to Supabase with IPv6...")
        
        # Use the IPv6 address directly
        conn = await asyncpg.connect(
            host="2406:da18:243:741d:6f5f:4e8b:cd71:fb8",  # IPv6 address
            port=int(os.getenv("DB_PORT", "5432")),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            ssl="require"
        )
        
        print("✅ Connection successful!")
        
        version = await conn.fetchval('SELECT version()')
        print(f"✅ PostgreSQL version: {version}")
        
        tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        print(f"✅ Existing tables: {[t['table_name'] for t in tables]}")
        
        await conn.close()
        print("✅ Connection closed successfully")
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_connection())