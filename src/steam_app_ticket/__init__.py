import io
import os
import steamid
import struct
import typing

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
from ipaddress import ip_address, IPv4Address, IPv6Address

STEAM_PUBLIC_KEY = b'''
-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDf7BrWLBBmLBc1OhSwfFkRf53T
2Ct64+AVzRkeRuh7h3SiGEYxqQMUeYKO6UWiSRKpI2hzic9pobFhRr3Bvr/WARvY
gdTckPv+T1JzZsuVcNfFjrocejN1oWI0Rrtgt4Bo+hOneoo3S57G9F1fOpn5nsQ6
6WOiu4gZKODnFMBCiQIBEQ==
-----END PUBLIC KEY-----
'''


class DLC(typing.NamedTuple):
    app_id: int
    licenses: tuple[int]


class AppTicket(typing.NamedTuple):
    auth_ticket: bytes
    gc_token: str
    token_generated: datetime
    session_external_ip: IPv4Address | IPv6Address
    client_connection_time: int
    client_connection_count: int
    version: int
    steam_id: steamid.SteamID
    app_id: int
    ownership_ticket_external_ip: IPv4Address | IPv6Address
    ownership_ticket_internal_ip: IPv4Address | IPv6Address
    ownership_flags: int
    ownership_ticket_generated: datetime
    ownership_ticket_expires: datetime
    licenses: list[int]
    dlc: tuple[DLC]


class ByteBuffer:
    def __init__(self, data):
        if not isinstance(data, bytes):
            data = bytes(data)

        self.stream = io.BytesIO(data)

    @property
    def limit(self):
        return self.stream.getbuffer().nbytes

    @property
    def position(self):
        return self.stream.tell()

    def read(self, length: int = 1):
        data = self.stream.read(length)
        return data

    def read_uint16(self):
        data = self.read(2)
        return struct.unpack('<H', data)[0]

    def read_uint32(self):
        data = self.read(4)
        return struct.unpack('<I', data)[0]

    def read_uint64(self):
        data = self.read(8)
        return struct.unpack('<Q', data)[0]

    def seek(self, offset: int, whence: int = 0):
        self.stream.seek(offset, whence)

    def skip(self, offset: int):
        self.stream.seek(offset, os.SEEK_CUR)


def parse_app_ticket(ticket: bytes, *, allow_invalid_signature: bool = False) -> AppTicket:
    if not isinstance(ticket, bytes):
        ticket = bytes.fromhex(ticket)
    stream = ByteBuffer(ticket)

    if stream.read_uint32() == 20:
        # full app ticket
        auth_ticket = ticket[stream.position - 4:stream.position - 4 + 52]

        gc_token = str(stream.read_uint64())
        stream.skip(8)  # SteamID
        token_generated = datetime.fromtimestamp(stream.read_uint32())
        session_header = stream.read_uint32()
        stream.skip(4)  # unknown 1
        stream.skip(4)  # unknown 2
        session_external_ip = ip_address(stream.read_uint32())
        stream.skip(4)  # filler
        client_connection_time = stream.read_uint32()
        client_connection_count = stream.read_uint32()

        if stream.read_uint32() + stream.position != stream.limit:
            raise ValueError()
    else:
        stream.seek(-4, os.SEEK_CUR)

    _ownership_ticket_offset = stream.position
    _ownership_ticket_length = stream.read_uint32()

    if (
        _ownership_ticket_offset + _ownership_ticket_length != stream.limit
    ) and (
        _ownership_ticket_offset + _ownership_ticket_length + 128 != stream.limit
    ):
        raise ValueError()

    version = stream.read_uint32()
    steam_id = steamid.SteamID(str(stream.read_uint64()))
    app_id = stream.read_uint32()

    ownership_ticket_external_ip = ip_address(stream.read_uint32())
    ownership_ticket_internal_ip = ip_address(stream.read_uint32())
    ownership_flags = stream.read_uint32()
    ownership_ticket_generated = datetime.fromtimestamp(stream.read_uint32())
    ownership_ticket_expires = datetime.fromtimestamp(stream.read_uint32())

    licenses = [stream.read_uint32() for _ in range(stream.read_uint16())]

    dlc = [
        DLC(
            app_id=stream.read_uint32(),
            licenses=[stream.read_uint32() for _ in range(stream.read_uint16())]
        ) for _ in range(stream.read_uint16())
    ]

    stream.skip(2)  # reserved

    if stream.position + 128 == stream.limit:
        signature = ticket[stream.position:stream.position + 128]

    if allow_invalid_signature is False:
        public_key = serialization.load_pem_public_key(STEAM_PUBLIC_KEY)
        try:
            public_key.verify(
                signature,
                ticket[_ownership_ticket_offset:_ownership_ticket_offset + _ownership_ticket_length],
                padding.PKCS1v15(),
                hashes.SHA1()
            )
        except InvalidSignature:
            return None
        except Exception:
            return None

    return AppTicket(**dict(
        auth_ticket=auth_ticket,
        gc_token=gc_token,
        token_generated=token_generated,
        session_external_ip=session_external_ip,
        client_connection_time=client_connection_time,
        client_connection_count=client_connection_count,
        version=version,
        steam_id=steam_id,
        app_id=app_id,
        ownership_ticket_external_ip=ownership_ticket_external_ip,
        ownership_ticket_internal_ip=ownership_ticket_internal_ip,
        ownership_flags=ownership_flags,
        ownership_ticket_generated=ownership_ticket_generated,
        ownership_ticket_expires=ownership_ticket_expires,
        licenses=licenses,
        dlc=dlc
    ))


def parse_encrypted_app_ticket(ticket: bytes, encryption_key: bytes | str):
    raise NotImplementedError()


if __name__ == '__main__':
    t = parse_app_ticket('14000000B27B493C5E56929B1EA7160401001001F8289966180000000100000002000000748742C19FCDF21600760000010000000C0100008C000000040000001EA7160401001001F0501400818D2D4E135A7C0A000000002A5A9866AA09B46601004FAB07000F005ADA15000000B4CA17000000B5CA17000000D61118000000D71118000000E13E180000002463180000002763180000006001190000004218190000004618190000007C38190000007D38190000007E38190000007F38190000000000A236FC69D30795D7046333685E8790B7AD54D80D878DB7BF6AC32864117E2EC3E03A70D09414F609DE25AB7A371367986C7648733E472B1C815100AF34AD37B0995C568E303360220A37CFC384FA44E492140DD8E410AE865C30E84A7C03FD04FFCBC3B23405759C05F460D970214CFB3FB48FD9C5AB48C073F6510D652B8AC5')
    print(t)
