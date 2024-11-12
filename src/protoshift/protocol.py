from .packet import Packet
from .packet_type import PacketType
from typing import Union
import re
import zlib


class Protocol:
    """Implementation of the Shifted packet radio protocol."""

    CALLSIGN_PATTERN = re.compile(r"^[A-Z0-9]{3,6}(?:-\d{1,2})?$")

    @staticmethod
    def validate_callsign(callsign: str) -> bool:
        """Validate that a callsign follows standard amateur radio format."""
        return bool(Protocol.CALLSIGN_PATTERN.match(callsign.upper()))

    @staticmethod
    def calculate_crc32(content: Union[str, bytes]) -> int:
        """Calculate CRC32 checksum of content."""
        if isinstance(content, str):
            content = content.encode("utf-8")
        return zlib.crc32(content) & 0xFFFFFFFF

    def encode(self, packet: Packet) -> bytes:
        """Encode a Packet object into bytes for transmission."""
        if not self.validate_callsign(packet.origin):
            raise ValueError(f"Invalid origin callsign: {packet.origin}")
        if not self.validate_callsign(packet.destination):
            raise ValueError(f"Invalid destination callsign: {packet.destination}")

        # Calculate CRC32 if not already present
        if packet.crc32 is None:
            packet.crc32 = self.calculate_crc32(packet.content)

        # Convert content to bytes if it's a string
        content_bytes = (
            packet.content.encode("utf-8")
            if isinstance(packet.content, str)
            else packet.content
        )

        # Construct the packet
        header = (
            f"{packet.origin.upper()}>{packet.destination.upper()}:{packet.type.value}"
        )
        header_bytes = header.encode("ascii")

        # Combine all parts with CRC32
        crc_bytes = packet.crc32.to_bytes(4, byteorder="big")
        return header_bytes + content_bytes + crc_bytes

    def decode(self, data: bytes) -> Packet:
        """Decode received bytes into a Packet object."""
        try:
            # Find the position of the content separator
            header_end = data.index(b":")
            addresses = data[:header_end].decode("ascii")

            # Split addresses and verify format
            origin, destination = addresses.split(">")

            # Get packet type
            packet_type = PacketType(chr(data[header_end + 1]))

            # Extract content (excluding CRC32)
            content_start = header_end + 2
            content_end = len(data) - 4
            content = data[content_start:content_end]

            # Extract and verify CRC32
            received_crc = int.from_bytes(data[-4:], byteorder="big")

            # Convert content to string if it's a text packet
            if packet_type == PacketType.TEXT:
                content = content.decode("utf-8")

            # Create and return packet
            packet = Packet(
                origin=origin,
                destination=destination,
                type=packet_type,
                content=content,
                crc32=received_crc,
            )

            # Verify CRC32
            calculated_crc = self.calculate_crc32(packet.content)
            if calculated_crc != received_crc:
                raise ValueError(
                    f"CRC32 mismatch: expected {calculated_crc}, got {received_crc}"
                )

            return packet

        except Exception as e:
            raise ValueError(f"Failed to decode packet: {str(e)}")

    def verify_packet(self, packet: Packet) -> bool:
        """Verify the integrity of a packet using its CRC32 checksum."""
        if packet.crc32 is None:
            return False
        return self.calculate_crc32(packet.content) == packet.crc32
