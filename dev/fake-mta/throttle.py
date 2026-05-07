#!/usr/bin/env python3
"""Fake MTA that always returns 421 4.7.0 [TSS04] on MAIL FROM.

Used in dev to validate Hedwig's transient-error handling end-to-end —
specifically that a 4xx response defers (and is retried) rather than
being permanently bounced.

The 421 message mirrors the real Yahoo TSS04 response so log assertions
can match on the same string format we see in production.
"""
import asyncio


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    print(f"connect from {peer}", flush=True)

    async def send(line: str) -> None:
        writer.write((line + "\r\n").encode())
        await writer.drain()
        print(f"-> {line}", flush=True)

    async def recv() -> str:
        data = await reader.readline()
        line = data.decode(errors="replace").rstrip("\r\n")
        if line:
            print(f"<- {line}", flush=True)
        return line

    await send("220 fake-throttle.test ESMTP ready")
    while True:
        try:
            line = await recv()
        except (ConnectionError, asyncio.IncompleteReadError):
            break
        if not line:
            break
        upper = line.upper()
        if upper.startswith("EHLO") or upper.startswith("HELO"):
            await send("250-fake-throttle.test")
            await send("250-PIPELINING")
            await send("250 SIZE 10485760")
        elif upper.startswith("MAIL FROM"):
            # The actual test signal: pretend we're Yahoo's TSS04 throttle.
            await send(
                "421 4.7.0 [TSS04] Messages from this IP temporarily deferred "
                "due to unexpected volume - see fake-throttle.test/tss04"
            )
            break
        elif upper.startswith("QUIT"):
            await send("221 bye")
            break
        elif upper.startswith("NOOP") or upper.startswith("RSET"):
            await send("250 ok")
        else:
            await send("502 not implemented")
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def main() -> None:
    server = await asyncio.start_server(handle, "0.0.0.0", 25)
    print("listening on 0.0.0.0:25", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
