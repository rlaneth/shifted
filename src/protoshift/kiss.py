class KISS:
    FEND = 0xC0  # Frame End
    FESC = 0xDB  # Frame Escape
    TFEND = 0xDC  # Transposed Frame End
    TFESC = 0xDD  # Transposed Frame Escape
    CMD_DATA = 0x00  # Data frame command

    @staticmethod
    def escape(data: bytes) -> bytes:
        """Escape special characters in KISS frame."""
        result = bytearray()
        for byte in data:
            if byte == KISS.FEND:
                result.extend([KISS.FESC, KISS.TFEND])
            elif byte == KISS.FESC:
                result.extend([KISS.FESC, KISS.TFESC])
            else:
                result.append(byte)
        return bytes(result)

    @staticmethod
    def frame(data: bytes) -> bytes:
        """Wrap data in KISS frame."""
        # FEND + Command byte + Escaped data + FEND
        return (
            bytes([KISS.FEND, KISS.CMD_DATA]) + KISS.escape(data) + bytes([KISS.FEND])
        )

    @staticmethod
    def unwrap(frame: bytes) -> bytes:
        """Extract data from KISS frame."""
        result = bytearray()
        i = 0
        while i < len(frame):
            if frame[i] == KISS.FESC:
                i += 1
                if i < len(frame):
                    if frame[i] == KISS.TFEND:
                        result.append(KISS.FEND)
                    elif frame[i] == KISS.TFESC:
                        result.append(KISS.FESC)
            else:
                result.append(frame[i])
            i += 1
        return bytes(result)
