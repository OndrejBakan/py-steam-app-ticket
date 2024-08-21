import collections
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


class DLC(typing.NamedTuple):
    app_id: int
    licenses: list[int]


class AppTicket(typing.NamedTuple):
    auth_ticket: bytes
    gc_token: str
    token_generated: datetime
    session_external_ip: IPv4Address|IPv6Address
    client_connection_time: int
    client_connection_count: int
    version: int
    steam_id: steamid.SteamID
    app_id: int
    ownership_ticket_external_ip: IPv4Address|IPv6Address
    ownership_ticket_internal_ip: IPv4Address|IPv6Address
    ownership_flags: int
    ownership_ticket_generated: datetime
    ownership_ticket_expires: datetime
    licenses: list[int]
    dlc: list[DLC]


class ByteBuffer:
    def __init__(self, data):
        if not isinstance(data, bytearray):
            data = bytearray(data)

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

class AppTicket:
    def __init__(self):
        self.__ticket = None
        self.__ownership_ticket_offset = None
        self.__ownership_ticket_length = None

        self.auth_ticket = None
        self.gc_token = None
        self.token_generated = None
        self.session_header = None
        self.session_external_ip = None
        self.client_connection_time = None
        self.client_connection_count = None
        self.version = None
        self.steam_id = None
        self.app_id = None
        self.ownership_ticket_external_ip = None
        self.ownership_ticket_internal_ip = None
        self.ownership_flags = None
        self.ownership_ticket_generated = None
        self.ownership_ticket_expires = None
        self.licenses = None
        self.dlc = None
        self.signature = None

    def parse(self, ticket):
        self.__ticket = ticket = bytes.fromhex(ticket)
        self.__stream = stream = ByteBuffer(ticket)

        length = stream.read_uint32()

        if length == 20:
            # full app ticket
            self.auth_ticket = ticket[stream.position - 4 : stream.position - 4 + 52]

            self.gc_token = stream.read_uint64()
            stream.skip(8) # SteamID
            self.token_generated = datetime.fromtimestamp(stream.read_uint32())
            self.session_header = stream.read_uint32()
            stream.skip(4) # unknown 1
            stream.skip(4) # unknown 2
            self.session_external_ip = ip_address(stream.read_uint32())
            stream.skip(4) # filler
            self.client_connection_time = stream.read_uint32()
            self.client_connection_count = stream.read_uint32()

            if stream.read_uint32() + stream.position != len(ticket):
                raise ValueError()
        else:
            stream.seek(-4, os.SEEK_CUR)

        self.__ownership_ticket_offset = stream.position
        self.__ownership_ticket_length = stream.read_uint32()

        if (
            self.__ownership_ticket_offset + self.__ownership_ticket_length != stream.limit
        ) and (
            self.__ownership_ticket_offset + self.__ownership_ticket_length + 128 != stream.limit
        ):
            raise ValueError()

        self.version = stream.read_uint32()
        self.steam_id = steamid.SteamID(str(stream.read_uint64()))
        self.app_id = stream.read_uint32()

        self.ownership_ticket_external_IP = ip_address(stream.read_uint32())
        self.ownership_ticket_internal_IP = ip_address(stream.read_uint32())
        self.ownership_flags = stream.read_uint32()
        self.ownership_ticket_generated = datetime.fromtimestamp(stream.read_uint32())
        self.ownership_ticket_expires = datetime.fromtimestamp(stream.read_uint32())

        self.licenses = [stream.read_uint32() for _ in range(stream.read_uint16())]

        self.dlc = [
            DLC(app_id=stream.read_uint32(),
                licenses=[stream.read_uint32() for _ in range(stream.read_uint16())]
            ) for _ in range(stream.read_uint16())
        ]

        stream.skip(2) # reserved

        if stream.position + 128 == stream.limit:
            self.signature = ticket[stream.position : stream.position + 128]

    def validate(self, public_key_file_path = None) -> bool:
        """
        Validates the ownership ticket part using a public key.

        Args:
            public_key_file_path (FileDescriptorOrPath): The file path to the public key in PEM format. If None, defaults to 'system.pem' in the current directory.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """

        if not public_key_file_path:
            public_key_file_path = os.path.join(os.path.dirname(__file__), 'system.pem')

        try:
            with open(public_key_file_path, 'rb') as public_key_file:
                public_key = serialization.load_pem_public_key(public_key_file.read())
        except Exception:
            raise

        try:
            public_key.verify(
                self.signature,
                self.__ticket[self.__ownership_ticket_offset : self.__ownership_ticket_offset + self.__ownership_ticket_length],
                padding.PKCS1v15(),
                hashes.SHA1()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


def parse_app_ticket(ticket: bytes, *, allow_invalid_signature: bool = False):
    pass

def parse_encrypted_app_ticket(ticket: bytes, encryption_key: bytes|str):
    pass


if __name__ == '__main__':
    parse_app_ticket(b'test', allow_invalid_signature=True)
