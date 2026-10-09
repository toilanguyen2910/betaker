import subprocess
import sys
import time

def probe_tree_kill():
    t0 = time.time()
    try:
        cmd = f'"{sys.executable}" -c "import time; time.sleep(10)"'
        print(f"Starting tree-kill probe with cmd: {cmd}")
        p = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        try:
            stdout, stderr = p.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
            else:
                p.kill()
            try:
                p.communicate(timeout=1)
            except Exception:
                pass
            raise
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        print(f"Caught TimeoutExpired with tree-kill! Total elapsed: {elapsed:.2f}s")

if __name__ == "__main__":
    probe_tree_kill()
