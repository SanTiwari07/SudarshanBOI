import subprocess

try:
    result = subprocess.run(
        ["docker", "logs", "--tail", "200", "sudarshanboi-backend-1"],
        capture_output=True, text=True, check=True
    )
    with open(r"d:\Projects\Sudarshan BOI\backend_logs.txt", "w", encoding="utf-8") as f:
        f.write(result.stdout)
        f.write("\n--- STDERR ---\n")
        f.write(result.stderr)
    print("Logs saved successfully.")
except Exception as e:
    print(f"Error getting logs: {e}")
