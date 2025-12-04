import psycopg2
import os

# Connect to database
conn = psycopg2.connect(
    dbname="appsec_db",
    user="postgres",
    password="postgres",
    host="localhost",
    port="5432"
)

cursor = conn.cursor()

# Read and execute SQL
with open('database/init_custom_rules.sql', 'r') as f:
    sql = f.read()
    cursor.execute(sql)

conn.commit()

# Verify tables created
cursor.execute("""
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public'
    AND (tablename LIKE '%rule%' OR tablename LIKE '%enhancement%')
""")
tables = cursor.fetchall()

cursor.close()
conn.close()

print("✅ Custom rules database schema created successfully")
print(f"📊 Created tables: {[t[0] for t in tables]}")
