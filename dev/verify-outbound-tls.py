#!/usr/bin/env python3
"""Verify opportunistic outbound TLS with the dev Docker DNS/SMTP harness.

Start dev DNS and leave 172.30.0.4 free (see verify-config-reload.py).
Pass a dev-image-compatible binary:
    python3 dev/verify-outbound-tls.py /path/to/hedwig

Exercises both queue backends with an untrusted, mismatched certificate and
with no STARTTLS. MTA-STS enforcement and shared-MX pool isolation are covered
by the Rust tests in worker/pool.rs. No messages leave the Docker network.
"""
import argparse
import json
import os
import pathlib
import runpy
import smtplib
import subprocess
import tempfile
import uuid

helpers = runpy.run_path(str(pathlib.Path(__file__).with_name("verify-config-reload.py")))
run, wait_for = helpers["run"], helpers["wait_for"]

SINK = r'''
import asyncio, json, pathlib, ssl, sys
use_tls = sys.argv[1] == "tls"
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/scratch/cert.pem", "/scratch/key.pem")
async def handle(reader, writer):
    async def reply(text):
        writer.write((text + "\r\n").encode())
        await writer.drain()
    try:
        await reply("220 fake-throttle.test ESMTP")
        while line := await reader.readline():
            command = line.upper()
            if command.startswith((b"EHLO", b"HELO")):
                if use_tls and writer.get_extra_info("ssl_object") is None:
                    await reply("250-fake-throttle.test\r\n250 STARTTLS")
                else:
                    await reply("250 fake-throttle.test")
            elif command.startswith(b"STARTTLS"):
                await reply("220 start TLS")
                await writer.start_tls(context)
            elif command.startswith(b"DATA"):
                await reply("354 send message")
                body = bytearray()
                while (line := await reader.readline()) not in (b".\r\n", b""):
                    body.extend(line)
                pathlib.Path("/scratch/message.eml").write_bytes(body)
                pathlib.Path("/scratch/delivery.json").write_text(json.dumps({
                    "encrypted": writer.get_extra_info("ssl_object") is not None,
                }))
                await reply("250 accepted")
            elif command.startswith(b"QUIT"):
                await reply("221 bye")
                break
            else:
                await reply("250 ok")
    finally:
        writer.close()
async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 25)
    print("sink ready", flush=True)
    async with server:
        await server.serve_forever()
asyncio.run(main())
'''


def verify(binary, backend, tls):
    suffix = uuid.uuid4().hex[:8]
    server, sink = f"hedwig-tls-{suffix}", f"hedwig-tls-sink-{suffix}"
    with tempfile.TemporaryDirectory(prefix="hedwig-tls-") as temporary:
        scratch = pathlib.Path(temporary)
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(scratch / "key.pem"), "-out", str(scratch / "cert.pem"),
            "-days", "1", "-subj", "/CN=unrelated.test",
            "-addext", "subjectAltName=DNS:unrelated.test")
        (scratch / "sink.py").write_text(SINK)
        (scratch / "config.toml").write_text(f'''[log]
level = "debug"
format = "json"
[server]
workers = 1
disable_outbound = false
outbound_local = false
helo_hostname = "sender.test"
[[server.listeners]]
addr = "0.0.0.0:2525"
[server.smtp]
min_idle = 0
max_size = 1
[storage]
storage_type = "{backend}"
base_path = "/scratch/spool"
''')
        try:
            run("docker", "run", "-d", "--name", sink, "--network", "smtp_test",
                "--ip", "172.30.0.4", "-v", f"{scratch}:/scratch",
                "python:3.12-slim", "python", "/scratch/sink.py", "tls" if tls else "plain")
            wait_for(lambda: "sink ready" in run("docker", "logs", sink), "SMTP sink")
            run("docker", "run", "-d", "--name", server, "--network", "smtp_test",
                "--dns", "172.30.0.2", "-p", "127.0.0.1::2525", "-v", f"{scratch}:/scratch",
                "-v", f"{binary}:/hedwig:ro", "dev-smtp:latest",
                "/hedwig", "--config", "/scratch/config.toml")
            port = int(run("docker", "port", server, "2525/tcp").strip().rsplit(":", 1)[1])
            client = wait_for(lambda: smtplib.SMTP("127.0.0.1", port, timeout=5), "Hedwig startup")
            with client:
                client.sendmail("sender@sender.test", ["recipient@throttle.test"],
                                f"From: sender@sender.test\r\nTo: recipient@throttle.test\r\n"
                                f"Subject: outbound TLS {suffix}\r\n\r\nhello\r\n")
            def delivery():
                path = scratch / "delivery.json"
                try:
                    return json.loads(path.read_text())
                except (FileNotFoundError, json.JSONDecodeError):
                    return None
            result = wait_for(delivery, "outbound delivery")
            assert result["encrypted"] == tls, result
            assert suffix.encode() in (scratch / "message.eml").read_bytes()
            def delivery_log():
                text = run("docker", "logs", server)
                return text if '"status":"delivered"' in text else None
            logs = wait_for(delivery_log, "delivery log")
            assert '"status":"deferred"' not in logs, logs
            assert '"status":"bounced"' not in logs, logs
            print(f"PASS {backend}: {'untrusted, mismatched certificate accepted over TLS' if tls else 'plaintext delivered without STARTTLS'}")
        except Exception:
            for name in (server, sink):
                subprocess.run(["docker", "logs", name], check=False)
            raise
        finally:
            for name in (server, sink):
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            run("docker", "run", "--rm", "-v", f"{scratch}:/scratch", "dev-smtp:latest",
                "chown", "-R", f"{os.getuid()}:{os.getgid()}", "/scratch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert binary.is_file(), binary
    for backend in ("log", "fs"):
        for tls in (True, False):
            verify(binary, backend, tls)
