#!/usr/bin/env python3

import socket
import yaml
import time
from datetime import datetime
from pathlib import Path
from protoshift import Protocol, PacketType, KISS


def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)


def save_binary_file(content: bytes, source: str, dest: str, base_path: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_{source}_{dest}"
    path = Path(base_path) / filename
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "wb") as f:
        f.write(content)
    return path


def extract_kiss_frames(data: bytes) -> list[bytes]:
    """Extract one or more KISS frames from received data"""
    frames = []
    current_frame = bytearray()
    in_frame = False

    for byte in data:
        if byte == KISS.FEND:
            if in_frame and len(current_frame) > 1:  # >1 to ensure we have command byte
                frames.append(bytes(current_frame))
            current_frame = bytearray()
            in_frame = True
        elif in_frame:
            current_frame.append(byte)

    return frames


def process_kiss_frame(frame: bytes) -> bytes:
    """Process a KISS frame and return the contained data"""
    if len(frame) < 1:
        raise ValueError("Empty KISS frame")

    # First byte is command
    command = frame[0] & 0x0F
    if command != KISS.CMD_DATA:  # We only handle data frames (command 0)
        raise ValueError(f"Unsupported KISS command: {command}")

    # Use KISS class to unwrap the data portion
    return KISS.unwrap(frame[1:])


def process_packet(packet, config):
    station_callsign = config["station"]["callsign"]
    monitor_mode = config["station"]["monitor_mode"]

    # Check if packet is for this station or broadcast
    if (
        not monitor_mode
        and packet.destination != station_callsign
        and packet.destination != "CQCQCQ"
    ):
        return

    print(f"\nReceived packet from {packet.origin} to {packet.destination}")

    if packet.type == PacketType.TEXT:
        print(f"Text message: {packet.content}")
    else:
        filepath = save_binary_file(
            packet.content,
            packet.origin,
            packet.destination,
            config["storage"]["received_files_path"],
        )
        print(f"Binary file saved to: {filepath}")


def main():
    config = load_config()
    protocol = Protocol()

    # Create socket and connect to remote TNC
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((config["tnc"]["host"], config["tnc"]["port"]))
        print(f"Connected to {config['tnc']['host']}:{config['tnc']['port']}")
        print(f"Station callsign: {config['station']['callsign']}")
        print(
            f"Monitor mode: {'enabled' if config['station']['monitor_mode'] else 'disabled'}"
        )

        buffer = bytearray()
        while True:
            try:
                # Receive data
                chunk = s.recv(1024)
                if not chunk:
                    print("Connection closed by remote host")
                    break

                buffer.extend(chunk)

                # Extract KISS frames from received data
                frames = extract_kiss_frames(buffer)
                if frames:
                    buffer.clear()  # Clear buffer after processing frames

                    for frame in frames:
                        # Process KISS frame to get packet data
                        packet_data = process_kiss_frame(frame)

                        # Decode packet and process it
                        packet = protocol.decode(packet_data)
                        process_packet(packet, config)

            except Exception as e:
                print(f"Error processing packet: {str(e)}")
                time.sleep(1)  # Add delay to prevent tight loop on errors


if __name__ == "__main__":
    main()
