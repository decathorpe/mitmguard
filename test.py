import asyncio

import mitmproxy_wireguard

print(f"{dir(mitmproxy_wireguard)=}")


async def main():
    server = None

    loop = asyncio.get_running_loop()

    async def handle_connection(connection_id: int):
        print("handle connection task")

        for _ in range(2):
            print("reading...")
            data = await server.tcp_read(connection_id, 4096)
            print(f"read complete. writing... {len(data)=} {data[:10]=} ")
            server.tcp_write(connection_id, data.upper())
            print("write complete. draining...")
            await server.tcp_drain(connection_id)
            print("drained.")
        print("closing...")
        server.tcp_close(connection_id)
        print("closed.")

    def on_event(event):
        # simple echo server
        print(f"{event=}")
        if isinstance(event, mitmproxy_wireguard.ConnectionEstablished):
            print(f"{event.src_addr=}")
            loop.call_soon_threadsafe(lambda: loop.create_task(handle_connection(event.connection_id)))
        elif isinstance(event, mitmproxy_wireguard.ConnectionClosed):
            print(f"Connection closed {event.connection_id=}")

    print("main")
    server = await mitmproxy_wireguard.start_server("", 51820, on_event)
    print(f"{server=}")

    #try:
    #    await server.tcp_drain(42)
    #except Exception as e:
    #     print(e)

    await asyncio.sleep(3000)
    print("dropping")
    del server
    # no more messages
    await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
