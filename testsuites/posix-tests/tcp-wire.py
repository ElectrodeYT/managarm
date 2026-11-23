#!/usr/bin/env python3
"""Test netserver against a scripted Ethernet peer on an isolated QEMU link.

Attach virtio-net-pci with MAC 52:54:00:12:34:56 to
    -netdev socket,id=tcp-test,listen=127.0.0.1:47670
In the guest CI script, run
    systemctl stop dhcpcd
    ip addr add 10.24.5.2/24 dev enx525400123456
    ip route add 10.24.5.0/24 dev enx525400123456
    MANAGARM_TCP_WIRE=1 posix-tests socket_tcp_wire
Pass the QEMU socket's port to this script. Start it before the guest test.
"""

import argparse
from dataclasses import dataclass
import socket
import struct
import time


GUEST_MAC = bytes.fromhex("525400123456")
PEER_MAC = bytes.fromhex("525400654321")
GUEST_IP = socket.inet_aton("10.24.5.2")
PEER_IP = socket.inet_aton("10.24.5.1")
GUEST_PORT = 15670
PEER_PORT = 15671
FIN, SYN, RST, ACK = 1, 2, 4, 16


def seq(value):
    return value & 0xffffffff


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(word[0] for word in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


@dataclass
class Segment:
    source: int
    dest: int
    start: int
    ack: int
    flags: int
    window: int
    data: bytes

    @property
    def end(self):
        return seq(self.start + len(self.data) + bool(self.flags & SYN) + bool(self.flags & FIN))


class Peer:
    def __init__(self, connection):
        self.connection = connection
        self.buffer = bytearray()
        self.pending = []
        self.completed = set()

    def frame(self, ethertype, data):
        frame = GUEST_MAC + PEER_MAC + struct.pack("!H", ethertype) + data
        self.connection.sendall(struct.pack("!I", len(frame)) + frame)

    def send(self, source, dest, start, ack=0, flags=ACK, window=4096, data=b""):
        options = struct.pack("!BBH", 2, 4, 256) if flags & SYN else b""
        tcp = struct.pack("!HHIIBBHHH", source, dest, seq(start), seq(ack),
                          (5 + len(options) // 4) << 4, flags, window, 0, 0) + options + data
        pseudo = PEER_IP + GUEST_IP + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, PEER_IP, GUEST_IP)
        self.frame(0x0800, ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:] + tcp)

    def receive(self, deadline):
        while True:
            if len(self.buffer) >= 4:
                length, = struct.unpack_from("!I", self.buffer)
                if len(self.buffer) >= length + 4:
                    frame = bytes(self.buffer[4:length + 4])
                    del self.buffer[:length + 4]
                    break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no matching TCP segment")
            self.connection.settimeout(remaining)
            chunk = self.connection.recv(65536)
            if not chunk:
                raise EOFError("QEMU Ethernet connection closed")
            self.buffer.extend(chunk)

        if frame[12:14] == b"\x08\x06":
            arp = frame[14:]
            if arp[6:8] == b"\x00\x01" and arp[24:28] == PEER_IP:
                self.frame(0x0806, arp[:6] + b"\x00\x02" + PEER_MAC + PEER_IP + arp[8:18])
            return None
        if (frame[12:14] != b"\x08\x00" or frame[23] != 6
                or frame[26:34] != GUEST_IP + PEER_IP):
            return None
        ip_size = (frame[14] & 0xf) * 4
        total, = struct.unpack_from("!H", frame, 16)
        tcp = frame[14 + ip_size:14 + total]
        source, dest, start, ack, offset, flags, window = struct.unpack_from("!HHIIBBH", tcp)
        pseudo = GUEST_IP + PEER_IP + struct.pack("!BBH", 0, 6, len(tcp))
        assert checksum(pseudo + tcp) == 0, "invalid TCP checksum"
        return Segment(source, dest, start, ack, flags, window, tcp[(offset >> 4) * 4:])

    def expect(self, match, timeout=5):
        deadline = time.monotonic() + timeout
        while True:
            for i, segment in enumerate(self.pending):
                if match(segment):
                    return self.pending.pop(i)
            segment = self.receive(deadline)
            if segment:
                self.pending.append(segment)

    def quiet(self, match, timeout):
        try:
            segment = self.expect(match, timeout)
        except TimeoutError:
            return
        raise AssertionError(f"unexpected TCP segment {segment}")


def active_open(peer, persist):
    syn = peer.expect(lambda s: s.dest == PEER_PORT and s.flags == SYN, 25)
    if not persist:
        retry = peer.expect(lambda s: s.source == syn.source and s.flags == SYN)
        assert retry == syn
    port = syn.source
    host = 50001 if persist else 40001
    guest = syn.end
    window = 0 if persist else 4096
    peer.send(PEER_PORT, port, host - 1, guest, SYN | ACK, window)

    def ack_only(s):
        return s.source == port and s.flags == ACK and not s.data and s.ack == host

    peer.expect(ack_only)
    if persist:
        probe = peer.expect(lambda s: s.source == port and s.data)
        assert probe.start == guest and probe.data == b"a"
        peer.send(PEER_PORT, port, host, guest, window=0)
        assert peer.expect(lambda s: s.source == port and s.data, 16) == probe
        # Answer the next probe with the reopened window after losing the earlier update.
        peer.send(PEER_PORT, port, host, guest)
        assert peer.expect(lambda s: s.source == port and s.data) == probe
        tail = peer.expect(lambda s: s.source == port and s.data)
        assert tail.start == seq(guest + 1) and tail.data == b"bcdef"
    else:
        initial = peer.expect(lambda s: s.source == port and s.data)
        assert initial.start == guest and initial.data == b"abcdef"
        # The first final ACK was lost. The repeated SYN-ACK should get the same ACK.
        peer.send(PEER_PORT, port, host - 1, guest, SYN | ACK)
        peer.expect(ack_only, 0.8)
        peer.send(PEER_PORT, port, host, guest + 3)
        tail = peer.expect(lambda s: s.source == port and s.data)
        assert tail.start == seq(guest + 3) and tail.data == b"def"

    peer.send(PEER_PORT, port, host, tail.end, data=b"P" if persist else b"R")
    host += 1
    fin = peer.expect(lambda s: s.source == port and s.flags & FIN)
    if not persist:
        assert peer.expect(lambda s: s.source == port and s.flags & FIN, 12) == fin
    peer.send(PEER_PORT, port, host, fin.end, FIN | ACK)

    def final_ack(s):
        return s.source == port and s.flags == ACK and not s.data and s.ack == host + 1

    peer.expect(final_ack)
    if not persist:
        # An exact-sequence RST must not end TIME_WAIT.
        peer.send(PEER_PORT, port, host + 1, flags=RST)
        peer.send(PEER_PORT, port, host, fin.end, FIN | ACK)
        peer.expect(final_ack)
    peer.completed.add(port)


def zero_window_abort(peer):
    syn = peer.expect(lambda s: s.dest == PEER_PORT and s.flags == SYN
                      and s.source not in peer.completed, 25)
    port = syn.source
    guest = syn.end
    host = 60001
    peer.send(PEER_PORT, port, host - 1, guest, SYN | ACK, window=0)
    peer.expect(lambda s: s.source == port and s.flags == ACK and s.ack == host)
    probe = peer.expect(lambda s: s.source == port and s.data, 20)
    assert probe.start == guest and probe.data == b"z"
    peer.send(PEER_PORT, port, host, guest, window=0)
    peer.send(PEER_PORT, port, host, guest, window=0, data=b"!")
    peer.expect(lambda s: s.source == port and s.flags & RST and s.start == guest)


def passive_open(peer, port, start, lose_syn_ack=False):
    peer.send(port, GUEST_PORT, start, flags=SYN)

    def syn_ack(s):
        return s.dest == port and s.flags == SYN | ACK

    response = peer.expect(syn_ack)
    assert response.ack == seq(start + 1)
    if lose_syn_ack:
        assert peer.expect(syn_ack) == response
        peer.send(port, GUEST_PORT, start, flags=SYN)
        assert peer.expect(syn_ack, 0.8) == response
    peer.send(port, GUEST_PORT, start + 1, response.end)
    return response.end


def recovery(peer):
    port = 15673
    start = 0xfffffffc
    reply = seq(start + 1)
    first = passive_open(peer, port, start, lose_syn_ack=True)

    def data(s):
        return s.dest == port and bool(s.data)

    def expect_data(i, timeout=5):
        segment = peer.expect(data, timeout)
        assert segment.start == seq(first + i * 256), (i, segment)
        assert segment.data == bytes([ord('a') + i]) * 256
        return segment

    for offset, count in ((0, 1), (1, 2), (3, 3)):
        flight = [expect_data(i) for i in range(offset, offset + count)]
        if offset == 3:
            for segment in flight:
                peer.send(port, GUEST_PORT, reply, segment.end)
        else:
            peer.send(port, GUEST_PORT, reply, flight[-1].end)

    flight = [expect_data(i) for i in range(6, 12)]
    for _ in (1, 3, 4, 5):
        peer.send(port, GUEST_PORT, reply, flight[0].start)
    expect_data(6, 0.8)
    peer.send(port, GUEST_PORT, reply, flight[2].start)
    expect_data(8, 0.8)
    guest = flight[-1].end
    peer.send(port, GUEST_PORT, reply, guest)
    peer.quiet(data, 1.2)

    # Buffer two overlapping ranges and FIN before the leading gap, crossing sequence wrap.
    peer.send(port, GUEST_PORT, reply + 4, guest, FIN | ACK, data=b"efg")
    peer.expect(lambda s: s.dest == port and s.ack == reply)
    peer.send(port, GUEST_PORT, reply + 2, guest, data=b"cdXX")
    peer.expect(lambda s: s.dest == port and s.ack == reply)
    peer.send(port, GUEST_PORT, reply, guest, data=b"abZ")
    next_seq = seq(reply + 8)
    peer.expect(lambda s: s.dest == port and s.flags == ACK and s.ack == next_seq)
    fin = peer.expect(lambda s: s.dest == port and s.flags & FIN)
    peer.send(port, GUEST_PORT, next_seq, fin.end, window=0)


def resets(peer):
    port = 15674
    next_seq = 41001
    peer.send(port, GUEST_PORT + 10, next_seq - 1, flags=SYN)
    refused = peer.expect(lambda s: s.dest == port and s.flags == RST | ACK)
    assert refused.start == 0 and refused.ack == next_seq

    guest = passive_open(peer, port, next_seq - 1)
    marker = peer.expect(lambda s: s.dest == port and s.data == b"!")
    assert marker.start == guest
    guest = marker.end
    peer.send(port, GUEST_PORT, next_seq, guest)
    peer.send(port, GUEST_PORT, next_seq + 65536, flags=RST)
    peer.quiet(lambda s: s.dest == port and s.flags == ACK and not s.data, 0.15)
    peer.send(port, GUEST_PORT, next_seq + 1, flags=RST)
    challenge = peer.expect(lambda s: s.dest == port and s.flags == ACK and not s.data)
    assert challenge.start == guest and challenge.ack == next_seq

    # Keep a second child in SYN_RECEIVED until the guest closes the listener.
    half_port = 15675
    half_start = 70000
    peer.send(half_port, GUEST_PORT, half_start, flags=SYN)
    syn_ack = peer.expect(lambda s: s.dest == half_port and s.flags == SYN | ACK)
    assert syn_ack.ack == half_start + 1
    peer.send(port, GUEST_PORT, next_seq, flags=RST)
    half_reset = peer.expect(lambda s: s.dest == half_port and s.flags == RST | ACK)
    assert half_reset.start == syn_ack.end and half_reset.ack == half_start + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, nargs="?", default=47670)
    args = parser.parse_args()
    deadline = time.monotonic() + 60
    while True:
        try:
            connection = socket.create_connection(("127.0.0.1", args.port), timeout=1)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    with connection:
        peer = Peer(connection)
        for name, test in (("active retransmissions", lambda: active_open(peer, False)),
                           ("zero-window probing", lambda: active_open(peer, True)),
                           ("zero-window abort", lambda: zero_window_abort(peer)),
                           ("NewReno and receive reassembly", lambda: recovery(peer)),
                           ("reset processing", lambda: resets(peer))):
            print(f"TCP wire test: {name}", flush=True)
            test()
    print("TCP wire tests passed")


if __name__ == "__main__":
    main()
