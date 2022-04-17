from collections.abc import Callable


class ConnectionEstablished:
    connection_id: int
    src_addr: tuple
    dst_addr: tuple



class DatagramReceived:
    src_addr: tuple
    dst_addr: tuple
    data: bytes


class Server:
    async def tcp_read(self, connection_id: int, n: int) -> bytes:
        pass

    async def tcp_drain(self, connection_id: int) -> None:
        pass

    def tcp_write(self, connection_id: int, data: bytes) -> None:
        pass

    def tcp_close(self, connection_id: int, half_close: bool = False) -> None:
        pass


async def start_server(
    host: str,
    port: int,
    on_event: Callable[ConnectionEstablished | DatagramReceived]
) -> Server:
    ...
