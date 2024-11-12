from .packet_type import PacketType
from dataclasses import dataclass
from typing import Union, Optional


@dataclass
class Packet:
    origin: str
    destination: str
    type: PacketType
    content: Union[str, bytes]
    crc32: Optional[int] = None
