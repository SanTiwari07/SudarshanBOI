
import asyncio
import sys
import json
import traceback

sys.path.append("/app")
from app.engines.frida_sandbox import run_frida_analysis

async def run():
    try:
        print("Starting Frida Dynamic Analysis inside container...")
        res = await run_frida_analysis("/app/test_sample.apk")
        with open("/app/dynamic_result.json", "w") as f:
            json.dump(res, f)
        if res.get("available"):
            print("SUCCESS: Dynamic Analysis Available")
        else:
            print("FAILED: " + str(res.get("error")))
    except Exception as e:
        print("EXCEPTION: " + str(e))
        traceback.print_exc()

asyncio.run(run())
    