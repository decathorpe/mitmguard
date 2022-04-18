import asyncio

import mitmproxy_wireguard

print(f"{dir(mitmproxy_wireguard)=}")


class Handler:
    async def handle_connection(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        peername = w.get_extra_info('peername')
        print(f"connection task {peername=}")
        for _ in range(2):
            print("reading...")
            data = await r.read(4096)
            print(f"read complete. writing... {len(data)=} {data[:10]=} ")
            w.write(data.upper())
            print("write complete. draining...")
            await w.drain()
            print("drained.")
        print("closing...")
        w.close()
        print("closed.")

    def receive_datagram(self, *args):
        print(f"{args=}")


async def main():
    server = None

    loop = asyncio.get_running_loop()

    h = Handler()

    """
    def on_event(event):
        # simple echo server
        print(f"{event=}")
        if isinstance(event, mitmproxy_wireguard.ConnectionEstablished):
            print(f"{event.src_addr=}")
            loop.call_soon_threadsafe(lambda: loop.create_task(handle_connection(event.connection_id)))
        elif isinstance(event, mitmproxy_wireguard.ConnectionClosed):
            print(f"Connection closed {event.connection_id=}")
    """

    print("main")
    server = await mitmproxy_wireguard.start_server("", 51820, h)
    print(f"{server=}")

    await asyncio.sleep(3000)
    print("dropping")
    del server
    # no more messages
    await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
