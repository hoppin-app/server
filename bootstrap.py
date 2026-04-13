#!/usr/bin/env python3
"""
HopChat Bootstrap Server
========================
A lightweight Kademlia bootstrap node + UDP hole punching coordinator.

Listens on UDP port 4001 by default.
All messages use the same JSON format as the iOS app.

libp2p update: NodeIDs are now SHA-256 (32 bytes / 256 bits) to match
the updated iOS client. The PeerRegistry XOR distance comparison works
on arbitrary-length hex strings so no routing logic needed to change.
"""

import asyncio
import json
import time
import hashlib
import uuid
import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("hopchat-bootstrap")

PORT = int(os.environ.get("HOPCHAT_PORT", 4001))

# Message type constants (must match iOS KadMessageType)
MSG_PING           = 0x01
MSG_PONG           = 0x02
MSG_FIND_NODE      = 0x03
MSG_FOUND_NODE     = 0x04
MSG_STORE          = 0x05
MSG_FIND_VALUE     = 0x06
MSG_FOUND_VALUE    = 0x07
MSG_CONNECT_REQ    = 0x08
MSG_CONNECT_ACCEPT = 0x09
MSG_CONNECT_DECLINE= 0x0A
MSG_CHAT           = 0x0B
MSG_CHAT_ACK       = 0x0C
MSG_HOLE_PUNCH     = 0x0D   # Coordinate hole punching
MSG_RELAY          = 0x0E   # TURN-style relay for symmetric NAT fallback

K = 20   # Kademlia bucket size


# ---------------------------------------------------------------------------
# Peer registry
# ---------------------------------------------------------------------------

@dataclass
class PeerInfo:
    node_id:   str    # hex node ID (64 hex chars = 32 bytes = SHA-256)
    phone:     str
    ip:        str    # public IP seen by server
    port:      int    # public port seen by server
    last_seen: float  # unix timestamp
    lan_ip:    str = ""
    lan_port:  int = 0


class PeerRegistry:
    def __init__(self, ttl: int = 300):
        self._peers: Dict[str, PeerInfo] = {}   # phone -> PeerInfo
        self._ttl = ttl

    def upsert(self, phone: str, node_id: str, ip: str, port: int,
               lan_ip: str = "", lan_port: int = 0) -> PeerInfo:
        info = PeerInfo(node_id=node_id, phone=phone,
                        ip=ip, port=port, last_seen=time.time(),
                        lan_ip=lan_ip or ip, lan_port=lan_port or port)
        self._peers[phone] = info
        return info

    def get(self, phone: str) -> Optional[PeerInfo]:
        p = self._peers.get(phone)
        if p and (time.time() - p.last_seen) < self._ttl:
            return p
        return None

    def all_live(self) -> list:
        now = time.time()
        return [p for p in self._peers.values()
                if (now - p.last_seen) < self._ttl]

    def closest(self, target_id_hex: str, k: int = K) -> list:
        """Return up to k peers closest (XOR distance) to target_id_hex."""
        target = int(target_id_hex, 16)
        live = self.all_live()
        live.sort(key=lambda p: int(p.node_id, 16) ^ target)
        return live[:k]

    def evict_stale(self):
        cutoff = time.time() - self._ttl
        stale = [k for k, v in self._peers.items() if v.last_seen < cutoff]
        for k in stale:
            del self._peers[k]
            log.info(f"Evicted stale peer: {k}")


# ---------------------------------------------------------------------------
# Key-value store (for STORE / FIND_VALUE)
# ---------------------------------------------------------------------------

class KVStore:
    def __init__(self, ttl: int = 600):
        self._data: Dict[str, tuple] = {}
        self._ttl = ttl

    def put(self, key: str, value: str):
        self._data[key] = (value, time.time())

    def get(self, key: str) -> Optional[str]:
        entry = self._data.get(key)
        if entry and (time.time() - entry[1]) < self._ttl:
            return entry[0]
        return None

    def evict_stale(self):
        cutoff = time.time() - self._ttl
        stale = [k for k, v in self._data.items() if v[1] < cutoff]
        for k in stale:
            del self._data[k]


# ---------------------------------------------------------------------------
# Node ID helpers  —  SHA-256 (32 bytes / 256 bits, matching iOS client)
# ---------------------------------------------------------------------------

def node_id_from_phone(phone: str) -> str:
    """Deterministic 256-bit NodeID from a phone string (hex, 64 chars)."""
    return hashlib.sha256(phone.encode()).hexdigest()

def bootstrap_node_id() -> str:
    """Fixed NodeID for this bootstrap server (256-bit)."""
    return hashlib.sha256(b"hopchat-bootstrap-server").hexdigest()

BOOTSTRAP_ID = bootstrap_node_id()


# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------

def make_message(msg_type: int, **kwargs) -> dict:
    return {
        "type":          msg_type,
        # senderID is now 32 bytes (SHA-256). list() on bytes() gives [int…].
        "senderID":      list(bytes.fromhex(BOOTSTRAP_ID)),
        "senderIP":      "0.0.0.0",   # clients ignore bootstrap's IP for routing
        "senderPort":    PORT,
        "senderPhone":   "bootstrap",
        "transactionID": str(uuid.uuid4()),
        "targetID":      None,
        "peers":         None,
        "key":           None,
        "value":         None,
        "chatBody":      None,
        "chatID":        None,
        "chatTimestamp": None,
        **kwargs,
    }

def peer_to_codable(p: PeerInfo, requester_ip: str = None) -> dict:
    """
    Return the best address for a peer given who's asking.
    If the requester shares a public IP with the peer they are behind the
    same NAT, so we return the LAN address for direct local communication.
    """
    use_lan = requester_ip and requester_ip == p.ip
    return {
        "id":    list(bytes.fromhex(p.node_id)),   # 32 bytes for SHA-256
        "ip":    p.lan_ip  if use_lan else p.ip,
        "port":  p.lan_port if use_lan else p.port,
        "phone": p.phone,
    }


def encode(msg: dict) -> bytes:
    return json.dumps(msg).encode()

def decode(data: bytes) -> Optional[dict]:
    try:
        return json.loads(data.decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# UDP Server
# ---------------------------------------------------------------------------

class BootstrapProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.registry = PeerRegistry(ttl=300)
        self.kv       = KVStore(ttl=600)
        self.transport: asyncio.DatagramTransport = None

        self._relay_count: int = 0

    def connection_made(self, transport):
        self.transport = transport
        log.info(f"Bootstrap server listening on UDP :{PORT}")

    def datagram_received(self, data: bytes, addr: tuple):
        msg = decode(data)
        if not msg:
            return

        ip, port  = addr
        phone     = msg.get("senderPhone", "unknown")
        node_id_bytes = msg.get("senderID", [])

        # senderID is 32 bytes (SHA-256). Fall back to deriving from phone if
        # the field is missing or has the old 20-byte SHA-1 length.
        if len(node_id_bytes) == 32:
            node_id = bytes(node_id_bytes).hex()
        else:
            # Old client or missing field — derive deterministically.
            node_id = node_id_from_phone(phone)
            if node_id_bytes:
                log.warning(f"  [{phone}] senderID has unexpected length "
                            f"{len(node_id_bytes)} bytes — using derived SHA-256 ID")

        tx_id     = msg.get("transactionID", str(uuid.uuid4()))
        msg_type  = msg.get("type", 0)

        # senderIP/senderPort in the payload is the client's LAN address.
        # `addr` (ip, port) is the real public address the OS observed.
        lan_ip    = msg.get("senderIP", ip)
        lan_port  = msg.get("senderPort", port)

        if phone not in ("unknown", "bootstrap"):
            self.registry.upsert(phone, node_id, ip, port, lan_ip, lan_port)
            log.info(f"[{phone}] {self._type_name(msg_type)} from {ip}:{port}"
                     f" (LAN {lan_ip}:{lan_port})")

        if msg_type == MSG_PING:
            self._handle_ping(tx_id, addr, phone, ip, port)

        elif msg_type == MSG_FIND_NODE:
            self._handle_find_node(msg, tx_id, addr, requester_ip=ip)

        elif msg_type == MSG_STORE:
            self._handle_store(msg, public_ip=ip, public_port=port)

        elif msg_type == MSG_FIND_VALUE:
            self._handle_find_value(msg, tx_id, addr, phone, requester_ip=ip)

        elif msg_type == MSG_CONNECT_REQ:
            self._handle_connect_request(msg, tx_id, addr, phone, ip, port)

        elif msg_type == MSG_RELAY:
            self._handle_relay(msg, addr, phone)

    # -----------------------------------------------------------------------

    def _handle_ping(self, tx_id: str, addr, phone: str, ip: str, port: int):
        """
        Reply with PONG, telling the peer its own public address.

        NAT note: `addr` is the (ip, port) tuple the OS gave us from recvfrom.
        This is the peer's *public* address as seen from the internet — the
        exact endpoint their router's NAT mapping points to.  We echo it back
        in key/value so the client can learn its own public port, which it
        cannot know until a packet comes back from outside.
        """
        pong = make_message(MSG_PONG, transactionID=tx_id)
        pong["key"]   = f"public-addr-{phone}"
        pong["value"] = f"{ip}:{port}"
        self._send(pong, addr)
        log.info(f"  → PONG to {phone} ({ip}:{port})")

        # Proactively share a few other live peers so the new node can
        # start building its routing table immediately.
        closest = self.registry.closest(node_id_from_phone(phone), k=5)
        closest = [p for p in closest if p.phone != phone]
        if closest:
            found = make_message(
                MSG_FOUND_NODE,
                peers=[peer_to_codable(p, requester_ip=ip) for p in closest]
            )
            self._send(found, addr)
            log.info(f"  → Sent {len(closest)} peers to {phone}")

    def _handle_find_node(self, msg: dict, tx_id: str, addr, requester_ip: str = None):
        target_bytes = msg.get("targetID") or []
        target_hex   = bytes(target_bytes).hex() if target_bytes else BOOTSTRAP_ID
        closest      = self.registry.closest(target_hex)
        reply = make_message(
            MSG_FOUND_NODE,
            transactionID=tx_id,
            peers=[peer_to_codable(p, requester_ip=requester_ip) for p in closest]
        )
        self._send(reply, addr)

    def _handle_store(self, msg: dict, public_ip: str = None, public_port: int = None):
        key   = msg.get("key")
        value = msg.get("value")
        if not (key and value):
            return

        # If the client is announcing its own address ("user-<phone>"),
        # override whatever LAN address it put in `value` with the real public
        # address observed from the datagram.  Peers outside the NAT need this.
        if key.startswith("user-") and public_ip:
            corrected = f"{public_ip}:{public_port}"
            if value != corrected:
                log.info(f"  STORE {key}: client said {value}, "
                         f"overriding with public addr {corrected}")
            self.kv.put(key, corrected)
        else:
            self.kv.put(key, value)

        log.info(f"  STORE {key} = {self.kv.get(key)}")

    def _handle_find_value(self, msg: dict, tx_id: str, addr,
                            phone: str, requester_ip: str = None):
        key = msg.get("key", "")

        # Fast path: peer address lookup ("user-<phone>")
        if key.startswith("user-"):
            target_phone = key[5:]
            peer = self.registry.get(target_phone)
            if peer:
                requester_peer = self.registry.get(phone)
                if requester_peer and requester_peer.ip == peer.ip:
                    # Same NAT → use LAN address for direct local comms
                    addr_to_return = f"{peer.lan_ip}:{peer.lan_port}"
                    log.info(f"  → Same NAT, returning LAN addr: {addr_to_return}")
                else:
                    addr_to_return = f"{peer.ip}:{peer.port}"
                reply = make_message(MSG_FOUND_VALUE, transactionID=tx_id,
                                     key=key, value=addr_to_return)
                self._send(reply, addr)
                log.info(f"  FOUND_VALUE {key} = {addr_to_return}")
                return

        # General KV lookup
        value = self.kv.get(key)
        if value:
            reply = make_message(MSG_FOUND_VALUE, transactionID=tx_id,
                                 key=key, value=value)
            self._send(reply, addr)
        else:
            closest = self.registry.closest(node_id_from_phone(key))
            reply = make_message(
                MSG_FOUND_NODE,
                transactionID=tx_id,
                peers=[peer_to_codable(p, requester_ip=requester_ip) for p in closest]
            )
            self._send(reply, addr)

    def _handle_connect_request(self, msg: dict, tx_id: str, addr,
                                 requester_phone: str, requester_ip: str,
                                 requester_port: int):
        """
        UDP Hole Punching coordination.
        A wants to connect to B:
          1. Look up B's public address in the registry.
          2. Send HOLE_PUNCH to A with B's public address.
          3. Send HOLE_PUNCH to B with A's public address.
        Both sides fire UDP simultaneously, opening the NAT mappings.
        """
        target_phone = msg.get("key", "")
        target_peer  = self.registry.get(target_phone)

        if not target_peer:
            log.info(f"  Hole punch: {target_phone} not found in registry")
            decline = make_message(MSG_CONNECT_DECLINE, transactionID=tx_id)
            self._send(decline, addr)
            return

        log.info(f"  Hole punch: {requester_phone} ({requester_ip}:{requester_port})"
                 f" <-> {target_phone} ({target_peer.ip}:{target_peer.port})")

        # Tell requester (A) where target (B) is
        notify_a = make_message(
            MSG_HOLE_PUNCH,
            transactionID=tx_id,
            key=target_phone,
            value=f"{target_peer.ip}:{target_peer.port}",
        )
        self._send(notify_a, addr)

        # Tell target (B) where requester (A) is
        notify_b = make_message(
            MSG_HOLE_PUNCH,
            transactionID=tx_id,
            key=requester_phone,
            value=f"{requester_ip}:{requester_port}",
        )
        self._send(notify_b, (target_peer.ip, target_peer.port))

        log.info(f"  Hole punch coords sent to both sides ✓")

    def _handle_relay(self, msg: dict, sender_addr, sender_phone: str):
        """
        TURN-style relay fallback for symmetric NAT.

        Flow:
          A  --RELAY(key=B, value=innerMsg)--> bootstrap
          bootstrap --RELAY(key=A, value=innerMsg, from A's addr)--> B
          B  --RELAY(key=A, value=replyMsg)--> bootstrap
          bootstrap --RELAY(key=B, value=replyMsg, from B's addr)--> A
        """
        target_phone = msg.get("key", "")
        inner_json   = msg.get("value", "")

        if not target_phone or not inner_json:
            log.warning(f"  RELAY from {sender_phone}: missing key or value")
            return

        target_peer = self.registry.get(target_phone)
        if not target_peer:
            log.info(f"  RELAY: {target_phone} not in registry, dropping")
            decline = make_message(MSG_CONNECT_DECLINE,
                                   key=target_phone, value="offline")
            self._send(decline, sender_addr)
            return

        try:
            inner_msg = json.loads(inner_json)
        except Exception:
            log.warning(f"  RELAY from {sender_phone}: inner payload not valid JSON")
            return

        # Stamp the sender's real public address so the receiver can reply.
        inner_msg["senderIP"]   = sender_addr[0]
        inner_msg["senderPort"] = sender_addr[1]

        forward = make_message(
            MSG_RELAY,
            key=sender_phone,
            value=json.dumps(inner_msg),
        )
        self._send(forward, (target_peer.ip, target_peer.port))

        self._relay_count += 1
        if self._relay_count % 100 == 1:
            log.info(f"  [relay] total forwarded: {self._relay_count}")
        else:
            log.debug(f"  RELAY {sender_phone} -> {target_phone} "
                      f"({len(inner_json)} bytes)")

    def _send(self, msg: dict, addr):
        try:
            self.transport.sendto(encode(msg), addr)
        except Exception as e:
            log.warning(f"Send error to {addr}: {e}")

    @staticmethod
    def _type_name(t: int) -> str:
        names = {
            0x01: "PING",        0x02: "PONG",          0x03: "FIND_NODE",
            0x04: "FOUND_NODE",  0x05: "STORE",         0x06: "FIND_VALUE",
            0x07: "FOUND_VALUE", 0x08: "CONNECT_REQ",   0x09: "CONNECT_ACCEPT",
            0x0A: "CONNECT_DECLINE", 0x0B: "CHAT",      0x0C: "CHAT_ACK",
            0x0D: "HOLE_PUNCH",  0x0E: "RELAY",
        }
        return names.get(t, f"UNKNOWN(0x{t:02X})")


# ---------------------------------------------------------------------------
# Maintenance loop
# ---------------------------------------------------------------------------

async def maintenance(registry: PeerRegistry, kv: KVStore, interval: int = 60):
    while True:
        await asyncio.sleep(interval)
        registry.evict_stale()
        kv.evict_stale()
        live = registry.all_live()
        log.info(f"[maintenance] {len(live)} live peers")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    loop = asyncio.get_running_loop()

    protocol_instance = BootstrapProtocol()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: protocol_instance,
        local_addr=("0.0.0.0", PORT)
    )

    log.info(f"HopChat bootstrap server started on UDP port {PORT}")
    log.info(f"Bootstrap node ID (SHA-256): {BOOTSTRAP_ID}")

    try:
        await maintenance(protocol_instance.registry, protocol_instance.kv)
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())