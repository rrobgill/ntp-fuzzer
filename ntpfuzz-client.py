#!/usr/bin/env python3
"""
NTPv4 client with packet fuzzing and comparision

This client generates NTP client requests with:
Valid data generated from current system time.
Replacing random bytes in valid packets and analyzing responses
Runs 1000 cycles, modifying valid NTP packets with random data

Licenced under GPLv2
"""

import socket
import sys
import struct
import time
import datetime
import argparse
import random
from ipaddress import ip_address

# NTP constants
NTP_PORT = 123
NTP_PACKET_FORMAT = "!12I"  # 48 bytes, 12 unsigned integers
NTP_DELTA = 2208988800  # Seconds between 1900-01-01 and 1970-01-01
NTP_PACKET_SIZE = 48  # Standard NTP packet size

def get_ip_addresses(domain):
    """
    Get both IPv4 and IPv6 addresses for a given domain name.
    """
    ipv4_addresses = []
    ipv6_addresses = []

    # Get IPv4 addresses
    try:
        ipv4_info = socket.getaddrinfo(domain, None, socket.AF_INET)
        ipv4_addresses = list(set(info[4][0] for info in ipv4_info))
    except socket.gaierror as e:
        print(f"Error resolving IPv4 address: {e}")

    # Get IPv6 addresses
    try:
        ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
        ipv6_addresses = list(set(info[4][0] for info in ipv6_info))
    except socket.gaierror as e:
        print(f"Error resolving IPv6 address: {e}")

    return ipv4_addresses, ipv6_addresses

def create_ntp_packet():
    """
    Create a valid NTP request packet.

    Returns:
        bytes: NTP request packet
    """
    # Create an empty packet
    packet = bytearray(48)
    packet[0] = 0b00100011  # 0x23 or 35 in decimal

    # Transmit timestamp (seconds since 1900-01-01)
    current_time = time.time() + NTP_DELTA
    # Encode as a 64-bit fixed-point number
    packet[40] = int(current_time) >> 24 & 0xFF
    packet[41] = int(current_time) >> 16 & 0xFF
    packet[42] = int(current_time) >> 8 & 0xFF
    packet[43] = int(current_time) & 0xFF

    return bytes(packet)

def fuzz_ntp_packet(valid_packet):
    """
    Replace random bytes in a valid NTP packet with random data.
    """
    # Convert to bytearray for modification
    packet = bytearray(valid_packet)

    # Generate a random number of bytes to replace (between 1 and 48)
    num_bytes_to_replace = random.randint(1, 48)

    # Choose random positions to replace
    positions_to_replace = random.sample(range(48), num_bytes_to_replace)

    # Replace bytes at chosen positions with random values
    for pos in positions_to_replace:
        packet[pos] = random.randint(0, 255)

    return bytes(packet), positions_to_replace

def is_valid_ntp_packet(packet):
    """
    Check if a packet is a valid NTP response.
    """
    # Check packet length
    if len(packet) != NTP_PACKET_SIZE:
        return False

    try:
        # Try to unpack the packet
        unpacked = struct.unpack(NTP_PACKET_FORMAT, packet)

        # Check for version (should be 3 or 4)
        version = ((unpacked[0] >> 24) >> 3) & 0x7
        if version not in [3, 4]:
            return False

        # Check for mode (should be 4 for server)
        mode = (unpacked[0] >> 24) & 0x7
        if mode != 4:
            return False

        # Check stratum (0-16 are valid)
        stratum = (unpacked[0] >> 16) & 0xFF
        if stratum > 16:
            return False

        return True
    except struct.error:
        return False

def hex_dump(data, prefix=''):
    """
    Create a hex dump of the given data.
    """
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_values = ' '.join(f'{byte:02x}' for byte in chunk)
        ascii_values = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
        result.append(f"{prefix}{i:04x}: {hex_values.ljust(48)} {ascii_values}")
    return '\n'.join(result)

def parse_ntp_packet(packet):
    """
    Parse an NTP response packet.
    """
    if len(packet) != 48:
        return None

    try:
        unpacked = struct.unpack(NTP_PACKET_FORMAT, packet)
    except struct.error:
        return None

    # First byte contains important flags
    flags = unpacked[0] >> 24

    # Extract the leap indicator, version, and mode
    leap_indicator = (flags >> 6) & 0x3
    version = (flags >> 3) & 0x7
    mode = flags & 0x7

    # Extract other fields
    stratum = (unpacked[0] >> 16) & 0xFF
    poll = (unpacked[0] >> 8) & 0xFF
    precision = unpacked[0] & 0xFF
    if precision > 127:
        precision -= 256

    # Extract timestamps (NTP has its own 64-bit fixed point format)
    root_delay = float(unpacked[1]) / 2**16
    root_dispersion = float(unpacked[2]) / 2**16
    ref_id = unpacked[3]

    # Reference timestamp
    ref_time_int = unpacked[4]
    ref_time_frac = unpacked[5]
    ref_time = ref_time_int + float(ref_time_frac) / 2**32 - NTP_DELTA

    # Originate timestamp
    orig_time_int = unpacked[6]
    orig_time_frac = unpacked[7]
    orig_time = orig_time_int + float(orig_time_frac) / 2**32 - NTP_DELTA

    # Receive timestamp
    recv_time_int = unpacked[8]
    recv_time_frac = unpacked[9]
    recv_time = recv_time_int + float(recv_time_frac) / 2**32 - NTP_DELTA

    # Transmit timestamp
    tx_time_int = unpacked[10]
    tx_time_frac = unpacked[11]
    tx_time = tx_time_int + float(tx_time_frac) / 2**32 - NTP_DELTA

    # Create a dict with all the parsed values
    ntp_data = {
        'leap_indicator': leap_indicator,
        'version': version,
        'mode': mode,
        'stratum': stratum,
        'poll': poll,
        'precision': precision,
        'root_delay': root_delay,
        'root_dispersion': root_dispersion,
        'ref_id': ref_id,
        'reference_time': ref_time,
        'originate_time': orig_time,
        'receive_time': recv_time,
        'transmit_time': tx_time
    }

    return ntp_data

def get_leap_indicator_name(leap_indicator):
    """Convert leap indicator value to human-readable string."""
    leap_indicators = {
        0: "no warning",
        1: "last minute of day has 61 seconds",
        2: "last minute of day has 59 seconds",
        3: "alarm condition (clock not synchronized)"
    }
    return leap_indicators.get(leap_indicator, "unknown")

def get_mode_name(mode):
    """Convert mode value to human-readable string."""
    modes = {
        0: "reserved",
        1: "symmetric active",
        2: "symmetric passive",
        3: "client",
        4: "server",
        5: "broadcast",
        6: "NTP control message",
        7: "private use"
    }
    return modes.get(mode, "unknown")

def get_stratum_description(stratum):
    """Convert stratum value to human-readable description."""
    if stratum == 0:
        return "unspecified or invalid"
    elif stratum == 1:
        return "primary reference (e.g., atomic clock)"
    elif 2 <= stratum <= 15:
        return f"secondary reference (synced to stratum {stratum-1})"
    else:
        return "reserved"

def format_timestamp(timestamp):
    """Format a UNIX timestamp as a readable date and time."""
    if timestamp == 0:
        return "N/A"
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')

def format_ref_id(stratum, ref_id):
    """Format the reference identifier based on stratum."""
    if stratum <= 1:
        # Primary reference source
        chars = []
        for i in range(4):
            byte = (ref_id >> (24 - i * 8)) & 0xFF
            if 32 <= byte <= 126:  # Printable ASCII
                chars.append(chr(byte))
            else:
                chars.append('.')
        return ''.join(chars)
    else:
        # IP address
        ip = ref_id
        return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"

def print_ntp_packet_details(ntp_data, title):
    """
    Print NTP packet details in human-readable format.
    """
    if ntp_data is None:
        print(f"{title}: Unable to parse packet")
        return

    print(f"\n=== {title} ===\n")

    # Basic info
    print(f"Leap Indicator: {ntp_data['leap_indicator']} ({get_leap_indicator_name(ntp_data['leap_indicator'])})")
    print(f"Version: {ntp_data['version']}")
    print(f"Mode: {ntp_data['mode']} ({get_mode_name(ntp_data['mode'])})")
    print(f"Stratum: {ntp_data['stratum']} ({get_stratum_description(ntp_data['stratum'])})")

    # More technical details
    print(f"Poll Interval: {ntp_data['poll']} ({2 ** ntp_data['poll']} seconds)")
    print(f"Precision: {ntp_data['precision']} ({2 ** ntp_data['precision']} seconds)")
    print(f"Root Delay: {ntp_data['root_delay'] * 1000:.6f} ms")
    print(f"Root Dispersion: {ntp_data['root_dispersion'] * 1000:.6f} ms")

    # Reference ID and timestamps
    print(f"Reference ID: 0x{ntp_data['ref_id']:08x} ({format_ref_id(ntp_data['stratum'], ntp_data['ref_id'])})")
    print(f"Reference Timestamp: {format_timestamp(ntp_data['reference_time'])}")
    print(f"Originate Timestamp: {format_timestamp(ntp_data['originate_time'])}")
    print(f"Receive Timestamp: {format_timestamp(ntp_data['receive_time'])}")
    print(f"Transmit Timestamp: {format_timestamp(ntp_data['transmit_time'])}")

def fuzz_ntp_server(address, num_cycles=1000, timeout=2):
    """
    Fuzz test an NTP server by sending packets with random bytes replaced.
    """
    # Determine if IPv4 or IPv6
    try:
        addr = ip_address(address)
        family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    except ValueError:
        print(f"Invalid IP address: {address}")
        return 0, 0, 0

    success_count = 0
    failure_count = 0
    timeout_count = 0

    print(f"\nStarting NTP fuzzing against {address} with {num_cycles} test cycles...")

    for cycle in range(1, num_cycles + 1):
        # Create a valid packet, then fuzz it
        valid_packet = create_ntp_packet()
        fuzzed_packet, modified_positions = fuzz_ntp_packet(valid_packet)

        # Create a UDP socket
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)

                # Send the fuzzed packet
                sock.sendto(fuzzed_packet, (address, NTP_PORT))

                # Receive response
                try:
                    response, _ = sock.recvfrom(4096)  # Allow for larger response

                    # Check if response is valid
                    if is_valid_ntp_packet(response):
                        success_count += 1
                        if cycle % 100 == 0 or cycle == 1:
                            print(f"Cycle {cycle}: Modified {len(modified_positions)} bytes. Got valid response.")
                    else:
                        failure_count += 1
                        print(f"\n\nCycle {cycle}: Invalid response detected!\n")
                        print(f"Sent packet: Modified {len(modified_positions)} bytes at positions {sorted(modified_positions)}")
                        print("\nOriginal packet hex dump:")
                        print(hex_dump(valid_packet))
                        print("\nFuzzed packet hex dump:")
                        print(hex_dump(fuzzed_packet))

                        print(f"\nReceived packet: {len(response)} bytes")
                        print("Received packet hex dump:")
                        print(hex_dump(response))

                        # Try to parse the packets for human-readable output
                        orig_data = parse_ntp_packet(valid_packet)
                        fuzz_data = None
                        resp_data = None

                        try:
                            fuzz_data = parse_ntp_packet(fuzzed_packet)
                        except Exception as e:
                            print(f"Error parsing fuzzed packet: {e}")

                        try:
                            if len(response) >= 48:
                                resp_data = parse_ntp_packet(response[:48])
                        except Exception as e:
                            print(f"Error parsing response: {e}")

                        print_ntp_packet_details(orig_data, "Original Valid NTP Packet")
                        print_ntp_packet_details(fuzz_data, "Fuzzed NTP Packet")
                        print_ntp_packet_details(resp_data, "Received Packet (Attempted Parse)")

                except socket.timeout:
                    timeout_count += 1
                    if cycle % 10 == 0:
                        print(f"Cycle {cycle}: Timeout")

        except socket.error as e:
            print(f"Cycle {cycle}: Socket error: {e}")
            failure_count += 1

        # Small sleep to avoid overwhelming the server
        time.sleep(0.05)

    return success_count, failure_count, timeout_count

def main():
    """ Parse commandline arguments and start server """
    parser = argparse.ArgumentParser(description="NTP Fuzzer - Test NTP servers with random byte replacement")
    parser.add_argument("domain", help="Domain name or IP address of NTP server")
    parser.add_argument("-c", "--cycles", type=int, default=1000, help="Number of test cycles (default: 1000)")
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout for NTP queries in seconds (default: 2)")
    parser.add_argument("--ipv4-only", action="store_true", help="Only query IPv4 addresses")
    parser.add_argument("--ipv6-only", action="store_true", help="Only query IPv6 addresses")
    parser.add_argument("-s", "--select", type=int, help="Query only the Nth address (0-based index)")

    args = parser.parse_args()

    # Check if input is an IP or domain
    try:
        ip_address(args.domain)
        # If this succeeds, it's an IP address
        addresses_to_query = [args.domain]
    except ValueError:
        # It's a domain name, resolve it
        ipv4_addresses, ipv6_addresses = get_ip_addresses(args.domain)

        # Print the IP addresses
        print(f"\nIP addresses for {args.domain}:")

        if ipv4_addresses and not args.ipv6_only:
            print("\nIPv4 Addresses:")
            for i, ip in enumerate(ipv4_addresses):
                print(f"  [{i}] {ip}")
        else:
            if not args.ipv6_only:
                print("\nNo IPv4 addresses found.")

        if ipv6_addresses and not args.ipv4_only:
            print("\nIPv6 Addresses:")
            for i, ip in enumerate(ipv6_addresses, start=len(ipv4_addresses) if not args.ipv6_only else 0):
                print(f"  [{i}] {ip}")
        else:
            if not args.ipv4_only:
                print("\nNo IPv6 addresses found.")

        # Prepare list of addresses to query
        addresses_to_query = []
        if not args.ipv6_only:
            addresses_to_query.extend(ipv4_addresses)
        if not args.ipv4_only:
            addresses_to_query.extend(ipv6_addresses)

        # If the user specified a specific address by index, use only that one
        if args.select is not None:
            if 0 <= args.select < len(addresses_to_query):
                addresses_to_query = [addresses_to_query[args.select]]
            else:
                print(f"Error: Selected index {args.select} is out of range.")
                sys.exit(1)

    # Start fuzzing each address
    for address in addresses_to_query:
        print(f"\n\n=== Starting NTP fuzzing on {address} ===")
        success, failure, timeout = fuzz_ntp_server(address, num_cycles=args.cycles, timeout=args.timeout)

        # Print summary
        print(f"\n=== Fuzzing Summary for {address} ===")
        print(f"Total test cycles: {args.cycles}")
        print(f"Successful responses: {success} ({success/args.cycles*100:.2f}%)")
        print(f"Invalid responses: {failure} ({failure/args.cycles*100:.2f}%)")
        print(f"Timeouts: {timeout} ({timeout/args.cycles*100:.2f}%)")

if __name__ == "__main__":
    main()
