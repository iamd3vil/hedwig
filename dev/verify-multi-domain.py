#!/usr/bin/env python3
"""Verify multi-domain DKIM against the Docker DNS/SMTP harness, for both queues.

Start dev DNS and leave 172.30.0.4 free (see verify-config-reload.py).
Run with an image-compatible binary:
  uv run --with dkimpy --with pynacl dev/verify-multi-domain.py /path/to/hedwig
Keys and queues are temporary; DKIM verification uses local public keys, no DNS.
"""
import argparse
import base64
import os
import pathlib
import runpy
import smtplib
import subprocess
import tempfile
import time
import uuid

import dkim

helpers = runpy.run_path(str(pathlib.Path(__file__).with_name("verify-config-reload.py")))
run, wait_for = helpers["run"], helpers["wait_for"]


def verify(binary, backend):
    suffix = uuid.uuid4().hex[:8]
    server, sink = f"hedwig-domains-{suffix}", f"hedwig-domains-sink-{suffix}"
    with tempfile.TemporaryDirectory(prefix="hedwig-domains-") as temporary:
        scratch = pathlib.Path(temporary)
        run("openssl", "genrsa", "-out", str(scratch / "rsa.key"), "2048")
        run("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(scratch / "ed.key"))
        rsa_public = subprocess.check_output(["openssl", "pkey", "-in", str(scratch / "rsa.key"), "-pubout", "-outform", "DER"])
        ed_public = subprocess.check_output(["openssl", "pkey", "-in", str(scratch / "ed.key"), "-pubout", "-outform", "DER"])[-32:]
        keys = {
            b"rsa._domainkey.first.test": b"v=DKIM1; k=rsa; p=" + base64.b64encode(rsa_public),
            b"ed._domainkey.second.test": b"v=DKIM1; k=ed25519; p=" + base64.b64encode(ed_public),
            b"rotated._domainkey.first.test": b"v=DKIM1; k=ed25519; p=" + base64.b64encode(ed_public),
        }
        def entry(domain, selector, key, kind="rsa", table="[[server.dkim]]"):
            return f'{table}\ndomain = "{domain}"\nselector = "{selector}"\nprivate_key = "/scratch/{key}"\nkey_type = "{kind}"\n'
        first = entry("first.test", "rsa", "rsa.key")
        second = entry("second.test", "ed", "ed.key", "ed25519")
        def config(entries):
            return f'''[log]
level = "info"
format = "json"
[server]
workers = 1
max_retries = 1
outbound_local = true
[[server.listeners]]
addr = "0.0.0.0:2525"
{entries}
[storage]
storage_type = "{backend}"
base_path = "/scratch/spool"
'''
        config_path = scratch / "config.toml"
        config_path.write_text(config(first + second))
        sink_code = helpers["SINK"].replace('            p = pathlib.Path("/scratch/messages")', '            if pathlib.Path("/scratch/hold").exists():\n                pathlib.Path("/scratch/held").touch()\n                while pathlib.Path("/scratch/hold").exists():\n                    await asyncio.sleep(0.05)\n            p = pathlib.Path("/scratch/messages")')
        (scratch / "sink.py").write_text(sink_code)
        try:
            run("docker", "run", "-d", "--name", sink, "--network", "smtp_test", "--ip", "172.30.0.4",
                "-v", f"{scratch}:/scratch", "python:3.12-slim", "python", "/scratch/sink.py")
            wait_for(lambda: "sink ready" in run("docker", "logs", sink), "SMTP sink")
            run("docker", "run", "-d", "--name", server, "--network", "smtp_test", "--dns", "172.30.0.2",
                "-p", "127.0.0.1::2525", "-v", f"{scratch}:/scratch", "-v", f"{binary}:/hedwig:ro",
                "dev-smtp:latest", "/hedwig", "--config", "/scratch/config.toml")
            port = int(run("docker", "port", server, "2525/tcp").strip().rsplit(":", 1)[1])
            def connect():
                client = smtplib.SMTP("127.0.0.1", port, timeout=5)
                client.ehlo()
                return client
            client = wait_for(connect, "Hedwig startup")
            def send(header, domain, selector):
                count = len(list((scratch / "messages").glob("*")))
                # The envelope intentionally differs from the visible From domain.
                client.sendmail("bounce@envelope.test", ["recipient@throttle.test"],
                                f"{header}\r\nTo: recipient@throttle.test\r\nSubject: domains\r\n\r\nhello\r\n")
                raw = wait_for(lambda: (scratch / "messages" / str(count)).read_bytes(), "signed delivery")
                assert f"d={domain}".encode() in raw and f"s={selector}".encode() in raw, raw
                assert dkim.verify(raw, dnsfunc=lambda name, **kw: keys.get(name.rstrip(b"."))), raw
            send("From: Alice <alice@FIRST.TEST>", "first.test", "rsa")
            send("From: Bob\r\n <bob@second.test>", "second.test", "ed")
            for header in ["From: a@unknown.test", "From: a@sub.first.test", "Subject: missing From",
                           "From: a@first.test\r\nFrom: b@second.test", "From: a@first.test, b@first.test",
                           "From: invalid", "From: <a@first.test", "From: a@first.test>", "From: group: a@first.test;"]:
                try:
                    client.sendmail("bounce@envelope.test", ["recipient@throttle.test"], f"{header}\r\n\r\nhello\r\n")
                except smtplib.SMTPDataError as error:
                    assert error.smtp_code == 550 and error.smtp_error.startswith(b"5.7.1"), error
                else:
                    raise AssertionError(f"accepted {header}")
            # A rejected DATA transaction leaves the session usable.
            send("From: a@first.test", "first.test", "rsa")
            def reload(entries, failure=False):
                before = len(run("docker", "logs", server))
                config_path.write_text(config(entries))
                run("docker", "kill", "--signal", "HUP", server)
                expected = "configuration reload failed" if failure else "configuration reload completed"
                wait_for(lambda: expected in run("docker", "logs", server)[before:].lower(), "reload")
            for invalid in [first + entry("FIRST.TEST", "rsa", "rsa.key"),
                            first + entry("third.test", "rsa", "missing.key")]:
                reload(invalid, failure=True)
                send("From: a@second.test", "second.test", "ed")
            reload(entry("first.test", "rotated", "ed.key", "ed25519") + second)
            send("From: a@first.test", "first.test", "rotated")
            reload(first)
            try:
                client.sendmail("bounce@envelope.test", ["recipient@throttle.test"], "From: a@second.test\r\n\r\nhello\r\n")
            except smtplib.SMTPDataError as error:
                assert error.smtp_code == 550
            else:
                raise AssertionError("removed domain accepted")
            # Legacy table signs unrelated From domains exactly as before.
            reload(entry("first.test", "rsa", "rsa.key", table="[server.dkim]"))
            send("From: a@unknown.test", "first.test", "rsa")
            # Hold the only worker on an earlier message while a second-domain
            # message is queued, then remove that domain before it is attempted.
            reload(first + second)
            (scratch / "hold").touch()
            client.sendmail("bounce@envelope.test", ["recipient@throttle.test"], "From: a@first.test\r\n\r\nblocker\r\n")
            wait_for(lambda: (scratch / "held").exists(), "worker blocked at sink")
            client.sendmail("bounce@envelope.test", ["recipient@throttle.test"], "From: a@second.test\r\n\r\npending\r\n")
            reload(first)
            before = len(run("docker", "logs", server))
            (scratch / "hold").unlink()
            wait_for(lambda: "Sending domain second.test is not configured" in run("docker", "logs", server)[before:], "queued domain removal defers and exhausts retries")
            logs = run("docker", "logs", server)[before:]
            assert '"status":"deferred"' in logs, logs
            assert '"status":"bounced"' not in logs, logs
            # With one allowed attempt the deferred message must eventually
            # move to the bounce archive, on both queue implementations.
            deadline = time.monotonic() + 110
            while time.monotonic() < deadline:
                if any(b"pending" in path.read_bytes() for path in (scratch / "spool" / "bounced").rglob("*") if path.is_file()):
                    break
                time.sleep(0.5)
            else:
                raise AssertionError("removed-domain message did not bounce after retry exhaustion")
            client.quit()
            print(f"PASS {backend}: RSA/Ed25519 signatures verified, From routing, rejection, rotation, atomic reload, legacy compatibility, queued domain removal defers and exhausts retries")
        except Exception:
            subprocess.run(["docker", "logs", server], check=False)
            raise
        finally:
            for name in (server, sink):
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            run("docker", "run", "--rm", "-v", f"{scratch}:/scratch", "dev-smtp:latest",
                "chown", "-R", f"{os.getuid()}:{os.getgid()}", "/scratch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert binary.is_file(), binary
    for backend in ("log", "fs"):
        verify(binary, backend)
