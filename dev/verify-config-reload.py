#!/usr/bin/env python3
"""Exercise SIGHUP reload against a real Hedwig process and Docker SMTP sink.

Start dev DNS first: docker compose -f dev/docker-compose.yml up -d dns
Stop the compose fake-throttle service before running: this verifier needs its
172.30.0.4 address on smtp_test. Do not run verifier instances concurrently.
Pass a Linux binary compatible with dev-smtp:latest. All generated secrets and
spool data live in a temporary directory. Requires Docker, Python 3 and openssl.
Run both backends:
    python3 dev/verify-config-reload.py /path/to/hedwig --backend log
    python3 dev/verify-config-reload.py /path/to/hedwig --backend fs
"""
import argparse
import json
import os
import pathlib
import smtplib
import ssl
import subprocess
import tempfile
import time
import uuid


SINK = r'''
import asyncio, pathlib
async def handle(reader, writer):
    async def reply(s):
        writer.write((s + "\r\n").encode()); await writer.drain()
    await reply("220 fake-throttle.test ESMTP")
    while line := await reader.readline():
        cmd = line.upper()
        if cmd.startswith((b"EHLO", b"HELO")):
            await reply("250 fake-throttle.test")
        elif cmd.startswith(b"DATA"):
            await reply("354 send mail")
            body = bytearray()
            while (line := await reader.readline()) not in (b".\r\n", b""):
                body.extend(line)
            p = pathlib.Path("/scratch/messages")
            p.mkdir(exist_ok=True)
            (p / str(len(list(p.iterdir())))).write_bytes(body)
            await reply("250 stored")
        elif cmd.startswith(b"QUIT"):
            await reply("221 bye"); break
        else:
            await reply("250 ok")
    writer.close()
async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 25)
    print("sink ready", flush=True)
    async with server: await server.serve_forever()
asyncio.run(main())
'''


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def wait_for(check, description):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, smtplib.SMTPException):
            pass
        time.sleep(0.1)
    raise AssertionError(f"timed out: {description}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--backend", choices=["log", "fs"], default="log")
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert binary.is_file(), binary
    suffix = uuid.uuid4().hex[:8]
    server, sink = f"hedwig-reload-{suffix}", f"hedwig-sink-{suffix}"
    context = ssl._create_unverified_context()
    with tempfile.TemporaryDirectory(prefix="hedwig-reload-") as temporary:
        scratch = pathlib.Path(temporary)
        for n in (1, 2):
            run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(scratch / f"tls{n}.key"), "-out", str(scratch / f"tls{n}.pem"),
                "-days", "1", "-subj", f"/CN=reload-{n}.test")
            run("openssl", "genrsa", "-out", str(scratch / f"dkim{n}.key"), "2048")
        (scratch / "sink.py").write_text(SINK)
        (scratch / "invalid.key").write_text(
            "-----BEGIN unpublished-secret-----\nYQ==\n-----END unpublished-secret-----\n")
        current = dict(password="old-secret", domain="old.test", generation=1, workers=1)

        def config(**changes):
            state = current | changes
            n = state["generation"]
            return f'''[log]
level = "{state.get('level', 'info')}"
format = "json"
[server]
workers = {state['workers']}
outbound_local = true
[[server.listeners]]
addr = "0.0.0.0:2525"
[server.listeners.tls]
cert_path = "/scratch/tls{n}.pem"
key_path = "/scratch/tls{n}.key"
mode = "starttls"
[[server.listeners]]
addr = "0.0.0.0:2465"
[server.listeners.tls]
cert_path = "/scratch/tls{n}.pem"
key_path = "/scratch/tls{n}.key"
mode = "implicit"
[[server.auth]]
username = "user"
password = "{state['password']}"
[server.dkim]
domain = "sender.test"
selector = "key{n}"
private_key = "/scratch/{state.get('dkim_path', f'dkim{n}.key')}"
[storage]
storage_type = "{args.backend}"
base_path = "/scratch/spool"
[[filters]]
type = "from_domain_filter"
domain = ["{state['domain']}"]
action = "allow"
[[filters]]
type = "to_domain_filter"
domain = ["{state['domain']}"]
action = "deny"
'''

        config_path = scratch / "config.toml"
        config_path.write_text(config())
        try:
            run("docker", "run", "-d", "--name", sink, "--network", "smtp_test", "--ip", "172.30.0.4",
                "-v", f"{scratch}:/scratch", "python:3.12-slim", "python", "/scratch/sink.py")
            wait_for(lambda: "sink ready" in run("docker", "logs", sink), "fake MTA startup")
            run("docker", "run", "-d", "--name", server, "--network", "smtp_test", "--dns", "172.30.0.2",
                "-p", "127.0.0.1::2525", "-p", "127.0.0.1::2465",
                "-v", f"{scratch}:/scratch", "-v", f"{binary}:/hedwig:ro",
                "dev-smtp:latest", "/hedwig", "--config", "/scratch/config.toml")
            port = int(run("docker", "port", server, "2525/tcp").strip().rsplit(":", 1)[1])
            tls_port = int(run("docker", "port", server, "2465/tcp").strip().rsplit(":", 1)[1])

            def connect():
                client = smtplib.SMTP("127.0.0.1", port, timeout=5)
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
                return client

            def authenticate(password, mechanism="PLAIN"):
                client = connect()
                client.user, client.password = "user", password
                try:
                    client.auth(mechanism, getattr(client, "auth_" + mechanism.lower().replace("-", "_")), initial_response_ok=mechanism != "LOGIN")
                except Exception:
                    client.close()
                    raise
                return client

            def cert():
                with smtplib.SMTP_SSL("127.0.0.1", tls_port, context=context, timeout=5) as client:
                    return client.sock.getpeercert(binary_form=True)

            existing = wait_for(lambda: authenticate("old-secret"), "startup")
            old_cert = cert()

            def deliver(client, domain, selector):
                count = len(list((scratch / "messages").glob("*")))
                client.sendmail(f"sender@{domain}", ["recipient@throttle.test"],
                                f"From: sender@{domain}\r\nTo: recipient@throttle.test\r\nSubject: reload\r\n\r\nhello\r\n")
                message = wait_for(lambda: (scratch / "messages" / str(count)).read_text(), "outbound delivery")
                if selector is None:
                    assert "DKIM-Signature:" not in message, message
                else:
                    assert "DKIM-Signature:" in message and f"s={selector}" in message, message

            deliver(existing, "old.test", "key1")
            assert "Signing email with DKIM" not in run("docker", "logs", server)
            pid = json.loads(run("docker", "inspect", server))[0]["State"]["Pid"]

            def reload(text, expected="configuration reload completed"):
                config_path.write_text(text)
                before = len(run("docker", "logs", server))
                run("docker", "kill", "--signal", "HUP", server)
                def outcome():
                    lines = run("docker", "logs", server)[before:]
                    if expected == "failure":
                        return lines if any(message in lines.lower() for message in
                                            ("configuration reload failed", "configuration reload rejected")) else None
                    return lines if expected in lines.lower() else None
                return wait_for(outcome, "reload log")

            current.update(password="new-secret", domain="new.test", generation=2)
            reload(config(level="debug"))
            for mechanism in ("PLAIN", "LOGIN", "CRAM-MD5"):
                with wait_for(lambda: authenticate("new-secret", mechanism), f"new {mechanism} credentials"):
                    pass
                try:
                    authenticate("old-secret", mechanism)
                except smtplib.SMTPAuthenticationError:
                    pass
                else:
                    raise AssertionError(f"old credentials accepted with {mechanism}")
            new_cert = cert()
            assert new_cert != old_cert, "implicit TLS certificate did not rotate"
            with connect() as client:
                assert client.sock.getpeercert(binary_form=True) != old_cert, "STARTTLS certificate did not rotate"
            # Existing authenticated sessions survive and send with the new signer.
            deliver(existing, "new.test", "key2")
            assert "Signing email with DKIM" in run("docker", "logs", server), "log level did not reload"
            # Hedwig closes sessions on filter rejection, so probe each separately.
            assert existing.mail("sender@old.test")[0] >= 500
            existing.close()
            client = authenticate("new-secret")
            assert client.mail("sender@new.test")[0] == 250
            assert client.rcpt("recipient@new.test")[0] >= 500
            client.close()
            for invalid in (config(workers=2, password="unpublished-secret"),
                            config(dkim_path="missing.key", password="unpublished-secret"),
                            config(dkim_path="invalid.key"),
                            config().replace("tls2.pem", "missing.pem"),
                            config().replace('[[server.auth]]\nusername = "user"\npassword = "new-secret"\n', ''),
                            "not valid TOML [", config(level="not-a-level")):
                outcome = reload(invalid, "failure")
                if 'workers = 2' in invalid:
                    assert 'server.workers' in outcome, "rejection did not name unsupported field"
                if 'missing.key' in invalid:
                    assert 'dkim' in outcome.lower() and 'read' in outcome.lower(), outcome
                if 'invalid.key' in invalid:
                    assert 'dkim' in outcome.lower() and 'parse' in outcome.lower(), outcome
                if 'missing.pem' in invalid:
                    events = [json.loads(line) for line in outcome.splitlines() if line.startswith('{')]
                    assert any(event['fields'].get('listener_index') == 0 and
                               'certificate' in str(event['fields']).lower() for event in events), outcome
                if 'not-a-level' in invalid:
                    assert 'log.level' in outcome, outcome
                with authenticate("new-secret") as client:
                    deliver(client, "new.test", "key2")
                assert cert() == new_cert, "failed reload changed TLS identity"
            # Reload also rereads key files when their configured paths do not change.
            (scratch / "tls2.pem").write_bytes((scratch / "tls1.pem").read_bytes())
            (scratch / "tls2.key").write_bytes((scratch / "tls1.key").read_bytes())
            reload(config())
            assert cert() == old_cert, "same-path TLS rotation was ignored"
            before = len(run("docker", "logs", server))
            with authenticate("new-secret") as client:
                deliver(client, "new.test", "key2")
            assert "Signing email with DKIM" not in run("docker", "logs", server)[before:], "log level did not decrease"
            without_dkim = config()
            start, end = without_dkim.index("[server.dkim]"), without_dkim.index("[storage]")
            reload(without_dkim[:start] + without_dkim[end:])
            with authenticate("new-secret") as client:
                deliver(client, "new.test", None)
            reload(config())
            with authenticate("new-secret") as client:
                deliver(client, "new.test", "key2")
            assert json.loads(run("docker", "inspect", server))[0]["State"]["Pid"] == pid
            logs = run("docker", "logs", server)
            assert not any(secret in logs for secret in ("old-secret", "new-secret", "unpublished-secret", "PRIVATE KEY")), "logs exposed secrets"
            # Block key loading at a FIFO so SIGINT lands inside reload, not
            # between select iterations. A nonblocking writer opens only once
            # Hedwig is waiting for the FIFO reader side.
            fifo = scratch / "blocked.key"
            os.mkfifo(fifo)
            config_path.write_text(config(dkim_path="blocked.key"))
            run("docker", "kill", "--signal", "HUP", server)
            fd = wait_for(lambda: os.open(fifo, os.O_WRONLY | os.O_NONBLOCK), "reload waiting on key FIFO")
            try:
                run("docker", "kill", "--signal", "INT", server)
                # Allow Tokio's other runtime threads to dispatch SIGINT while
                # the reload thread remains blocked on the key read.
                time.sleep(0.5)
                os.write(fd, b"invalid test key")
            finally:
                os.close(fd)
            wait_for(lambda: not json.loads(run("docker", "inspect", server))[0]["State"]["Running"],
                     "SIGINT during reload initiates shutdown")
            state = json.loads(run("docker", "inspect", server))[0]["State"]
            assert state["ExitCode"] == 0, state
            assert "shutdown complete" in run("docker", "logs", server)
            print(f"PASS ({args.backend}): delivery, DKIM/TLS rotation, all auth mechanisms, filters, rollback, same PID, SIGINT during reload")
        except Exception:
            subprocess.run(["docker", "logs", server], check=False)
            raise
        finally:
            for name in (server, sink):
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "run", "--rm", "-v", f"{scratch}:/scratch", "dev-smtp:latest",
                            "chown", "-R", f"{os.getuid()}:{os.getgid()}", "/scratch"], check=True)


if __name__ == "__main__":
    main()
