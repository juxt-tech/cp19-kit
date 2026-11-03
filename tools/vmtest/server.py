"""Host side of the practice-VM test harness. PRACTICE VMs ONLY - never on a competition image.

Bind it to the VMware host-only/NAT adapter address (e.g. 192.168.209.1), never to 0.0.0.0.

  python -I server.py 192.168.209.1 8765 [STATE_DIR]

Guest -> host (agents):
  GET  /a | /l                      Windows / Linux bootstrap (installs the agent as a service)
  GET  /g/<name>                    agent + helper scripts from guest/  ({{SERVER}} filled in)
  GET  /f/<name>                    staged files (STATE/files: kit.zip, cp-config.txt, ...)
  GET  /<vm>/next?after=N           lowest queued job number > N  (200 + X-Job header, or 404)
  GET  /<vm>/kill-<n>               200 if the host asked to kill job n
  POST /<vm>/r/<name>               results: out-<n>.txt, hb.json, any upload
Host -> guest: vmt.ps1 writes STATE/vms/<vm>/q/cmd-<n>.(ps1|sh) and kill-<n>.
"""
import http.server, os, re, shutil, sys, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
GUEST = os.path.join(HERE, "guest")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
JOB = re.compile(r"^cmd-(\d+)\.(ps1|sh)$")


def ok(name):
    return bool(name) and bool(NAME.match(name))


class H(http.server.BaseHTTPRequestHandler):
    server_version = "cpvmtest/2"

    def log_message(self, fmt, *args):  # one short line per request, to stdout
        sys.stdout.write("%s %s\n" % (self.address_string(), fmt % args)); sys.stdout.flush()

    def send_text(self, code, text, headers=None):
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def send_file(self, path, template=False):
        if not os.path.isfile(path):
            return self.send_text(404, "not found")
        if template:  # scripts: fill in the server URL, keep LF/CRLF as stored
            with open(path, "r", encoding="utf-8", newline="") as f:
                return self.send_text(200, f.read().replace("{{SERVER}}", self.server.base))
        self.send_response(200)
        text = path.endswith((".txt", ".ps1", ".psm1", ".sh", ".json"))
        self.send_header("Content-Type", "text/plain; charset=utf-8" if text else "application/octet-stream")
        self.send_header("Content-Length", str(os.path.getsize(path)))
        self.end_headers()
        with open(path, "rb") as f:
            shutil.copyfileobj(f, self.wfile)

    def vmdir(self, vm, sub):
        d = os.path.join(self.server.state, "vms", vm, sub); os.makedirs(d, exist_ok=True); return d

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); parts = [p for p in u.path.split("/") if p]
        if parts in (["a"], ["l"]):
            return self.send_file(os.path.join(GUEST, "win-bootstrap.ps1" if parts == ["a"] else "linux-bootstrap.sh"), True)
        if len(parts) == 2 and parts[0] == "g" and ok(parts[1]):
            return self.send_file(os.path.join(GUEST, parts[1]), True)
        if len(parts) == 2 and parts[0] == "f" and ok(parts[1]):
            return self.send_file(os.path.join(self.server.state, "files", parts[1]))
        if len(parts) == 2 and ok(parts[0]) and parts[1] == "next":
            after = int((urllib.parse.parse_qs(u.query).get("after") or ["0"])[0] or 0)
            q = self.vmdir(parts[0], "q")
            jobs = sorted((int(m.group(1)), n) for n in os.listdir(q) for m in [JOB.match(n)] if m and int(m.group(1)) > after)
            if not jobs:
                return self.send_text(404, "no job")
            n, name = jobs[0]
            with open(os.path.join(q, name), "r", encoding="utf-8-sig") as f:
                return self.send_text(200, f.read(), {"X-Job": str(n)})
        if len(parts) == 2 and ok(parts[0]) and re.match(r"^kill-\d+$", parts[1]):
            hit = os.path.isfile(os.path.join(self.vmdir(parts[0], "q"), parts[1]))
            return self.send_text(200 if hit else 404, "kill" if hit else "no")
        self.send_text(404, "not found")

    def do_POST(self):
        parts = [p for p in urllib.parse.urlparse(self.path).path.split("/") if p]
        if not (len(parts) == 3 and ok(parts[0]) and parts[1] == "r" and ok(parts[2])):
            return self.send_text(400, "bad path")
        n = int(self.headers.get("Content-Length", 0))
        if n > 64 * 1024 * 1024:
            return self.send_text(413, "too big")
        dest = os.path.join(self.vmdir(parts[0], "r"), parts[2])
        with open(dest + ".part", "wb") as f:
            left = n
            while left > 0:
                chunk = self.rfile.read(min(left, 1 << 20))
                if not chunk:
                    break
                f.write(chunk); left -= len(chunk)
        os.replace(dest + ".part", dest)  # host never reads a half-written result
        self.send_text(200, "ok")


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: server.py BIND_IP PORT [STATE_DIR]")
    ip, port = sys.argv[1], int(sys.argv[2])
    if ip in ("0.0.0.0", "::", ""):
        sys.exit("bind to the VMware adapter IP (e.g. 192.168.209.1), not every interface")
    state = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.expanduser("~"), "cpvmtest")
    os.makedirs(os.path.join(state, "files"), exist_ok=True)
    srv = http.server.ThreadingHTTPServer((ip, port), H)
    srv.state, srv.base = state, "http://%s:%d" % (ip, port)
    print("cpvmtest server on %s  state=%s" % (srv.base, state)); sys.stdout.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
