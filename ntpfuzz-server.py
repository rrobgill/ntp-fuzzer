#!/usr/bin/env python3
"""
NTPv4 server with packet fuzzing capabilities

This server responds to NTP client requests with:
- Responses based valid packets using the current system time,
- stratum 2, RefID 'Xntp', small random root dispersion & delay.
- User options to introduce error in server time offset (fixed
- and/or jittery), and random variation to root characteristics.
- Random errors can also be introduced into the response packets

Licenced under GPLv2
"""

import socket
import struct
import time
import random
import ipaddress
import sys
from datetime import datetime

# NTP Constants
NTP_PORT = 123
NTP_PACKET_FORMAT = "!BBBbII4sQQQQ"  # 48 bytes NTP packet
NTP_PACKET_SIZE = 48
EPOCH_DELTA = 2208988800  # Seconds between 1900 (NTP epoch) and 1970 (Unix epoch)

# NTP Modes
NTP_MODE_BROADCAST = 2
NTP_MODE_CLIENT = 3
NTP_MODE_SERVER = 4

# Reference ID for upstream server (Xntp)
REF_ID = bytes([0x58, 0x6e, 0x74, 0x70])

SERVER_IP = "0.0.0.0"
USER_DEFAULT = 0

def ntp_time():
    """Convert current system time to NTP timestamp format."""
    now = time.time() + EPOCH_DELTA
    return int(now), int((now % 1) * 2**32)

def decode_ntp_packet(data):
    """Decode an NTP packet and return its components."""
    # Ensure we have at least NTP_PACKET_SIZE bytes
    if len(data) < NTP_PACKET_SIZE:
        raise ValueError(f"Packet too small: {len(data)} bytes (expected at least {NTP_PACKET_SIZE})")

    # Only use the first NTP_PACKET_SIZE bytes
    data = data[:NTP_PACKET_SIZE]

    # Unpack the first 48 bytes according to NTPv4 format
    unpacked = struct.unpack(NTP_PACKET_FORMAT, data)

    # Extract components for clearer display
    first_byte = unpacked[0]
    leap_indicator = (first_byte >> 6) & 0x3
    version = (first_byte >> 3) & 0x7
    mode = first_byte & 0x7
    stratum = unpacked[1]
    poll = unpacked[2]
    precision = unpacked[3]
    root_delay = float(unpacked[4]) / 2**16
    root_dispersion = float(unpacked[5]) / 2**16

    # Reference ID is now a 4-byte string
    ref_id_bytes = unpacked[6]
    ref_id = int.from_bytes(ref_id_bytes, byteorder='big')

    # The timestamps are now 64-bit values (Q format)
    ref_timestamp = float(unpacked[7]) / 2**32
    orig_timestamp = float(unpacked[8]) / 2**32
    recv_timestamp = float(unpacked[9]) / 2**32
    trans_timestamp = float(unpacked[10]) / 2**32

    # Refid as IP and text
    ref_id_str = '.'.join(str(b) for b in ref_id_bytes)
    ref_id_str = ref_id_str + " (" + ref_id_bytes.decode('ascii', errors='replace') + ")"

    # Convert NTP timestamps to datetime
    def ntp_to_datetime(timestamp):
        if timestamp == 0:
            return "Not set"
        try:
            return datetime.fromtimestamp(timestamp - EPOCH_DELTA).strftime('%Y-%m-%d %H:%M:%S.%f')
        except (ValueError, OverflowError):
            return "Invalid timestamp"

    return {
        "leap_indicator": leap_indicator,
        "version": version,
        "mode": mode,
        "stratum": stratum,
        "poll": poll,
        "precision": precision,
        "root_delay": root_delay,
        "root_dispersion": root_dispersion,
        "ref_id": ref_id,
        "ref_id_str": ref_id_str,
        "ref_timestamp": ref_timestamp,
        "ref_timestamp_str": ntp_to_datetime(ref_timestamp),
        "orig_timestamp": orig_timestamp,
        "orig_timestamp_str": ntp_to_datetime(orig_timestamp),
        "recv_timestamp": recv_timestamp,
        "recv_timestamp_str": ntp_to_datetime(recv_timestamp),
        "trans_timestamp": trans_timestamp,
        "trans_timestamp_str": ntp_to_datetime(trans_timestamp)
    }

def create_response_packet(received_data, offset, jitter, delay, dispersion):
    """Create a valid NTP response packet based on received data.
    Adjust as specified by user"""

    # Extract necessary fields from the received packet
    first_byte = received_data[0]
    mode = first_byte & 0x7
    poll = received_data[2]

    # Prepare response fields
    leap_indicator = 0  # No warning
    version = 4  # NTPv4
    mode = NTP_MODE_SERVER
    stratum = 2  # Secondary reference
    precision = -20  # About 1 microsecond

    # Root delay and dispersion - small values (25µs, 10µs) reasonable for stratum 2
    # add random error if requested by user
    root_delay = int((0.025 + random.gauss(delay,delay/3)) * 2**16)
    root_dispersion = int(0.01 + random.gauss(dispersion,dispersion/3) * 2**16)

    # Reference identifier
    reference_id = REF_ID

    # Get current time
    # adjust for specified offset and jitter
    now = time.time() + EPOCH_DELTA + offset + random.gauss(jitter, jitter/3)

    # For 64-bit timestamp packing
    def split_timestamp(timestamp):
        seconds = int(timestamp)
        fraction = int((timestamp - seconds) * 2**32)
        return (seconds << 32) | fraction

    # Receive timestamp (when request arrived)
    recv_timestamp = split_timestamp(now)

    # Reference timestamp (last updated - 10 minutes ago)
    ref_timestamp = split_timestamp(now - 600)

    # Extract originate timestamp from received packet (bytes 40-47)
    # This is the transmit timestamp from the client
    orig_timestamp_bytes = received_data[40:48]
    orig_timestamp = int.from_bytes(orig_timestamp_bytes, byteorder='big')

    # First byte: leap indicator, version, and mode
    first_byte = (leap_indicator << 6) | (version << 3) | mode

    # Transmit timestamp (time response sent)
    trans_timestamp = split_timestamp(now)

    # Pack the response
    response = struct.pack(
        NTP_PACKET_FORMAT,
        first_byte, stratum, poll, precision,
        root_delay, root_dispersion, reference_id,
        ref_timestamp, orig_timestamp, recv_timestamp, trans_timestamp
    )

    return response

def fuzz_packet(packet_data, max_rand):
    """Generate unreliable data"""
    packet = bytearray(packet_data)

    # Decide how many bytes to modify
    num_bytes_to_modify = random.randint(1, max_rand)

    # Choose random positions to modify
    positions = random.sample(range(NTP_PACKET_SIZE), num_bytes_to_modify)

    # Modify each selected byte
    for pos in positions:
        packet[pos] = random.randint(0, 255)

    return bytes(packet)

def hex_dump(data, prefix=''):
    """Create a nicely formatted hex dump of packet data."""
    result = []

    for j in range(0, len(data), 16):
        hex_values = ' '.join(f'{b:02x}' for b in data[j:j+16])
        ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[j:j+16])
        line = f"{prefix}{j:04x}: {hex_values:<47} |{ascii_values}|"
        result.append(line)

    return '\n'.join(result)

def print_packet_details(packet_data, title):
    """Print both hex dump and human-readable details of a packet."""
    print(f"\n=== {title} ===")
    print("Hex dump:")
    print(hex_dump(packet_data))

    print("\nHuman-readable details:")
    packet_info = decode_ntp_packet(packet_data)

    print(f"Leap Indicator: {packet_info['leap_indicator']}")
    print(f"Version: {packet_info['version']}")
    print(f"Mode: {packet_info['mode']} ({['Reserved', 'Symmetric Active', 'Symmetric Passive', 'Client', 'Server', 'Broadcast', 'Control', 'Private'][packet_info['mode']] if 0 <= packet_info['mode'] <= 7 else 'Unknown'})")
    print(f"Stratum: {packet_info['stratum']}")
    print(f"Poll Interval: {packet_info['poll']} ({2**packet_info['poll']} seconds)")
    print(f"Precision: {packet_info['precision']} ({2**packet_info['precision']:.9f} seconds)")
    print(f"Root Delay: {packet_info['root_delay']:.6f} seconds")
    print(f"Root Dispersion: {packet_info['root_dispersion']:.6f} seconds")
    print(f"Reference ID: {packet_info['ref_id_str']} (0x{packet_info['ref_id']:08x})")
    print(f"Reference Timestamp: {packet_info['ref_timestamp_str']} ({packet_info['ref_timestamp']:.9f})")
    print(f"Origin Timestamp: {packet_info['orig_timestamp_str']} ({packet_info['orig_timestamp']:.9f})")
    print(f"Receive Timestamp: {packet_info['recv_timestamp_str']} ({packet_info['recv_timestamp']:.9f})")
    print(f"Transmit Timestamp: {packet_info['trans_timestamp_str']} ({packet_info['trans_timestamp']:.9f})")

def run_server(host, port, max_rand, offset, jitter, delay, dispersion):
    """Run the NTP server."""
    # Create a UDP socket, bail if it doesn't work
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((host, port))
    except PermissionError:
        print("No permission to open socket. You may need to try sudo ntpfuzz-server")
        sys.exit(1)

    print(f"Server started on {host}:{port}")
    print("Waiting for NTP client requests...\n")

    try:
        while True:
            # Receive client request - increased buffer size to 512 bytes
            client_data, client_address = server_socket.recvfrom(512)
            print(f"\nReceived NTP request from {client_address[0]}:{client_address[1]}")

            # Process if the packet is at least NTP_PACKET_SIZE
            if len(client_data) >= NTP_PACKET_SIZE:
                # Display received packet
                print_packet_details(client_data, "Received Client Packet")
                if client_data[0] &0x07 == 3:
                    # Use only the first NTP_PACKET_SIZE bytes for response generation
                    valid_response = create_response_packet(client_data[:NTP_PACKET_SIZE], offset, jitter, delay, dispersion)
                    print_packet_details(valid_response, "Response Packet")

                    if max_rand > 0:
                        # Fuzz the response
                        fuzzed_response = fuzz_packet(valid_response,max_rand)
                        print_packet_details(fuzzed_response, "Fuzzed response Packet")
                        response = fuzzed_response
                    else:
                        response = valid_response

                    # Send the fuzzed response
                    server_socket.sendto(response, client_address)
                    print(f"\nSent NTP response to {client_address[0]}:{client_address[1]}")
                else:
                    print("\nNon client mode packet received, no reply...")
            else:
                print(f"Received packet too small ({len(client_data)} bytes), ignoring...")

    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()
        print("Server socket closed")

if __name__ == "__main__":
    # Allow custom port via command line argument
    # Usage ntpfuzz-server
    # Usage: ntpfuzz-server [ip <address>] [<port number>] [rand <number of bytes>] past future jitter
    # Command line options:
    # ip (ip address)
    # port (port number)
    # rand (maximum number of bytes to randomize per packet)
    # Example: ntpfuzz-server ip 127.0.0.1 port 53 rand 10
    # To start a server on localhost port 5053 randomising no more than 10 bytes
    server_port = NTP_PORT
    server_ip = SERVER_IP
    user_max_rand = USER_DEFAULT
    user_jitter = USER_DEFAULT
    user_offset = USER_DEFAULT
    user_delay = USER_DEFAULT
    user_dispersion = USER_DEFAULT

    # Parse command line arguments
    i = 1
    while i < len(sys.argv):
        if sys.argv[i].lower() == "ip" and i + 1 < len(sys.argv):
            try:
                # Validate IP address
                ipaddress.ip_address(sys.argv[i + 1])
                server_ip = sys.argv[i + 1]
                i += 2
            except ValueError:
                print(f"Invalid IP address: {sys.argv[i + 1]}")
                sys.exit(1)
        elif sys.argv[i].lower() == "port" and i + 1 < len(sys.argv):
            try:
                user_port = int(sys.argv[i + 1])
                if 1 <= user_port <= 65535:
                    server_port = user_port
                else:
                    print(f"Port number must be between 1 and 65535: {sys.argv[i + 1]}")
                    sys.exit(1)
                i += 2
            except ValueError:
                print(f"Invalid port number: {sys.argv[i + 1]}")
                sys.exit(1)
        elif sys.argv[i].lower() == "fuzz" and i + 1 < len(sys.argv):
            try:
                rand_val = int(sys.argv[i + 1])
                if 0 <= rand_val <= 48:
                    user_max_rand = rand_val
                else:
                    print(f"Random bytes value must be between 0 and 48: {sys.argv[i + 1]}")
                    sys.exit(1)
                i += 2
            except ValueError:
                print(f"Invalid random bytes value: {sys.argv[i + 1]}")
                sys.exit(1)
        elif sys.argv[i].lower() == "jitter" and i + 1 < len(sys.argv):
            try:
                user_jitter = float(sys.argv[i+1])
                if 0 <= user_jitter <= 1000:
                    user_jitter = user_jitter / 1000 # (convert to seconds)
                else:
                    print(f"Jitter time must be between 0 and 1000 ms: {sys.argv[i + 1]}")
                    sys.exit(1)
                i += 2
            except ValueError:
                print(f"Invalid jitter value: {sys.argv[i + 1]}")
                sys.exit(1)
        elif sys.argv[i].lower() == "delay" and i + 1 < len(sys.argv):
            try:
                user_delay = float(sys.argv[i+1])
                if 0 <= user_delay <= 1000:
                    user_delay = user_delay / 1000
                else:
                    print(f"Root delay variation time must be between 0 and 1000 ms: {sys.argv[i + 1]}")
                    sys.exit(1)
                i += 2
            except ValueError:
                print(f"Invalid root delay variation value: {sys.argv[i + 1]}")
                sys.exit(1)
        elif sys.argv[i].lower() == "dispersion" and i + 1 < len(sys.argv):
            try:
                user_dispersion = float(sys.argv[i+1])
                if 0 <= user_dispersion <= 1000:
                    user_dispersion = user_dispersion / 1000
                else:
                    print(f"Root dispertion variation time must be between 0 and 1000 ms: {sys.argv[i + 1]}")
                    sys.exit(1)
                i += 2
            except ValueError:
                print(f"Invalid root dispersion variation value: {sys.argv[i + 1]}")
                sys.exit(1)

        elif sys.argv[i].lower() == "offset" and i + 1 < len(sys.argv):
            try:
                user_offset = float(sys.argv[i+1])
                if abs(user_offset) >= 86401:
                    print(f"Offset time must be between -86400 and 86400 s: {sys.argv[i + 1]}")
                    sys.exit(1)
                i += 2
            except ValueError:
                print(f"Invalid offset values: {sys.argv[i + 1]}")
                sys.exit(1)


	# Boolean options
        elif sys.argv[i].lower() == "delay":
            user_delay = True
            i += 1
        elif sys.argv[i].lower() == "dispersion":
            user_dispersion = True
            i += 1
        else:
            print(f"Unknown or incomplete argument: {sys.argv[i]}")
            print("Usage: ntpfuzz-server [ip <address>] [port <number>] [fuzz <number of bytes>]")
            print("                      [offset <s>] [jitter <ms>] [delay <ms>] [dispersion<ms>]")
            sys.exit(1)

    print(f"Starting NTP fuzzing server on {server_ip}:{server_port}")
    if user_offset == user_jitter == user_dispersion == user_delay == 0:
        print("with no adjustment to server time or root characteristics")
    if user_offset > 0:
        print(f"server time calculations are offset to the future by {user_offset} s")
    if user_offset < 0:
        print(f"server time calculations are offset to the past by {abs(user_offset)} s")
    if user_jitter > 0:
        print(f"simulating normally distributed jitter of {user_jitter*1000} ms")
    if user_dispersion > 0:
        print(f"simulating normally distributed variation in root dispersion of {user_dispersion*1000} ms")
    if user_delay > 0:
        print(f"simulating normally distributed variation in root delay of {user_delay*1000} ms")
    if user_max_rand > 0:
        print(f"replacing between 1 and {user_max_rand} bytes per packet with random data")
    print("\n")
    run_server(host=server_ip, port=server_port, max_rand=user_max_rand, offset=user_offset, jitter=user_jitter, delay=user_delay, dispersion=user_dispersion)
