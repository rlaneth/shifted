#!/usr/bin/env python3

import argparse
import socket
import yaml
from protoshift import Protocol, Packet, PacketType, KISS


def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)


def send_packet(host: str, port: int, packet: bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        kiss_frame = KISS.frame(packet)
        s.sendall(kiss_frame)


def main():
    parser = argparse.ArgumentParser(description="Send messages via KISS TNC")
    parser.add_argument(
        "-d",
        "--destination",
        default="CQCQCQ",
        help="Destination callsign (default: CQCQCQ)",
    )
    parser.add_argument(
        "-b", "--binary", action="store_true", help="Send as binary message"
    )
    parser.add_argument(
        "-f",
        "--file",
        action="store_true",
        help="Read content from file instead of using it directly",
    )
    parser.add_argument(
        "content", help="Message content or file path if -f is specified"
    )
    args = parser.parse_args()
    config = load_config()
    protocol = Protocol()

    # Validate callsigns
    if not protocol.validate_callsign(config["station"]["callsign"]):
        print(f"Invalid station callsign: {config['station']['callsign']}")
        return
    if not protocol.validate_callsign(args.destination):
        print(f"Invalid destination callsign: {args.destination}")
        return

    # Determine content and type
    try:
        if args.file:
            mode = "rb" if args.binary else "r"
            with open(args.content, mode) as f:
                content = f.read()
        else:
            content = args.content
            if args.binary:
                content = content.encode()
    except OSError as e:
        print(f"Failed to read file: {str(e)}")
        return

    # Create and encode packet
    packet = Packet(
        origin=config["station"]["callsign"],
        destination=args.destination,
        type=PacketType.BINARY if args.binary else PacketType.TEXT,
        content=content,
    )
    encoded_packet = protocol.encode(packet)

    # Send packet
    try:
        send_packet(config["tnc"]["host"], config["tnc"]["port"], encoded_packet)
        print(f"Message sent to {args.destination}")
    except Exception as e:
        print(f"Failed to send message: {str(e)}")


if __name__ == "__main__":
    main()
