import sqlite3
import json

try:
    conn = sqlite3.connect(r"d:\Projects\Sudarshan BOI\backend\sudarshan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT sha256, dynamic_result FROM cases ORDER BY created_at DESC LIMIT 1")
    row = cursor.fetchone()
    if row:
        sha256, dynamic_str = row
        print(f"SHA256: {sha256}")
        if dynamic_str:
            dynamic = json.loads(dynamic_str)
            print(f"Dynamic available: {dynamic.get('available')}")
            print(f"Dynamic error: {dynamic.get('error')}")
            print(f"Multi-stage summary: {json.dumps(dynamic.get('multi_stage_summary', {}), indent=2)}")
        else:
            print("No dynamic_result at all (column is NULL).")
    else:
        print("No cases found.")
except Exception as e:
    print(f"Error: {e}")
