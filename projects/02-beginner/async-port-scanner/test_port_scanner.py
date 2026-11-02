import asyncio
import socket

import pytest

from port_scanner import parse_ports, scan


def test_parse_ports_ranges_and_dedup():
    assert parse_ports("22,80,79-81") == [22, 79, 80, 81]
    with pytest.raises(ValueError):
        parse_ports("0,70000")


def test_scan_finds_local_open_port_and_banner():
    async def run():
        async def handler(reader, writer):
            writer.write(b"SSH-2.0-TestServer\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        # find a port that is very likely closed
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
        s.close()
        async with server:
            return port, closed, await scan("127.0.0.1", [port, closed], timeout=1, banners=True)

    port, closed, results = asyncio.run(run())
    by_port = {r.port: r for r in results}
    assert by_port[port].state == "open"
    assert by_port[port].banner.startswith("SSH-2.0")
    assert by_port[closed].state == "closed"
