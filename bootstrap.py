#!/usr/bin/env python3
"""
HopChat Bootstrap Server
========================
A lightweight Kademlia bootstrap node + UDP hole punching coordinator.

Deploy on any VPS with a public IP:
    pip install -r requirements.txt
    python3 bootstrap.py

Listens on UDP port 4001 by default.
All messages use the same JSON format as the iOS app.
"""

import asyncio
import json
import time
import hashlib
import uuid
import logging
import os
from dataclasses import dataclass, asdict
from typing import Dict, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("hopchat-bootstrap")

PORT = int(os.environ.get("HOPCHAT_PORT", 4001))

# Message type constants (must match iOS KadMessageType)
MSG_PING          = 0x01
MSG_PONG          = 0x02
MSG_FIND_NODE     = 0x03
MSG_FOUND_NODE    = 0x04
MSG_STORE         = 0x05
MSG_FIND_VALUE    = 0x06
MSG_FOUND_VALUE   = 0x07
MSG_CONNECT_REQ   = 0x08
MSG_CONNECT_ACCEPT= 0x09
MSG_CONNECT_DECLINE=0x0A
MSG_CHAT          = 0x0B
MSG_CHAT_ACK      = 0x0C
MSG_HOLE_PUNCH    = 0x0D   # Coordinate hole punching
MSG_RELAY         = 0x0E   # TURN-style relay for symmetric NAT fallback

K = 20   # Kademlia bucket size


# ---------------------------------------------------------------------------
# Peer registry
# ---------------------------------------------------------------------------

@dataclass
class PeerInfo:
    node_id:    str        # hex node ID
    phone:      str
    ip:         str        # public IP seen by server
    port:       int        # public port seen by server
    last_seen:  float      # unix timestamp


class PeerRegistry:
    def __init__(self, ttl: int = 300):
        self._peers: Dict[str, PeerInfo] = {}   # phone -> PeerInfo
        self._ttl = ttl

    def upsert(self, phone: str, node_id: str, ip: str, port: int) -> PeerInfo:
        info = PeerInfo(node_id=node_id, phone=phone,
                        ip=ip, port=port, last_seen=time.time())
        self._peers[phone] = info
        return info

    def get(self, phone: str) -> Optional[PeerInfo]:
        p = self._peers.get(phone)
        if p and (time.time() - p.last_seen) < self._ttl:
            return p
        return None

    def all_live(self) -> list[PeerInfo]:
        now = time.time()
        return [p for p in self._peers.values()
                if (now - p.last_seen) < self._ttl]

    def closest(self, target_id_hex: str, k: int = K) -> list[PeerInfo]:
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
        self._data: Dict[str, tuple[str, float]] = {}
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
# Node ID helpers
# ---------------------------------------------------------------------------

def node_id_from_phone(phone: str) -> str:
    return hashlib.sha1(phone.encode()).hexdigest()

def bootstrap_node_id() -> str:
    return hashlib.sha1(b"hopchat-bootstrap-server").hexdigest()

BOOTSTRAP_ID = bootstrap_node_id()


# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------

def make_message(msg_type: int, **kwargs) -> dict:
    return {
        "type":        msg_type,
        "senderID":    list(bytes.fromhex(BOOTSTRAP_ID)),
        "senderIP":    "0.0.0.0",   # clients ignore bootstrap's IP for routing
        "senderPort":  PORT,
        "senderPhone": "bootstrap",
        "transactionID": str(uuid.uuid4()),
        "targetID":    None,
        "peers":       None,
        "key":         None,
        "value":       None,
        "chatBody":    None,
        "chatID":      None,
        "chatTimestamp": None,
        **kwargs,
    }

def peer_to_codable(p: PeerInfo) -> dict:
    return {
        "id":    list(bytes.fromhex(p.node_id)),
        "ip":    p.ip,
        "port":  p.port,
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

        # hole_punch_waiters: phone -> (addr, loop future)
        # When A wants to reach B, we note A is waiting; when B contacts us
        # we send both sides each other's address simultaneously.
        self._hp_waiters: Dict[str, tuple] = {}

        # relay stats for logging
        self._relay_count: int = 0

    def connection_made(self, transport):
        self.transport = transport
        log.info(f"Bootstrap server listening on UDP :{PORT}")

    def datagram_received(self, data: bytes, addr: tuple):
        msg = decode(data)
        if not msg:
            return

        ip, port = addr
        phone    = msg.get("senderPhone", "unknown")
        node_id_bytes = msg.get("senderID", [])
        node_id  = bytes(node_id_bytes).hex() if node_id_bytes else node_id_from_phone(phone)
        tx_id    = msg.get("transactionID", str(uuid.uuid4()))
        msg_type = msg.get("type", 0)

        # Always register/refresh the peer with their REAL public address
        if phone != "unknown" and phone != "bootstrap":
            self.registry.upsert(phone, node_id, ip, port)
            log.info(f"[{phone}] {self._type_name(msg_type)} from {ip}:{port}")

        if msg_type == MSG_PING:
            self._handle_ping(tx_id, addr, phone, ip, port)

        elif msg_type == MSG_FIND_NODE:
            self._handle_find_node(msg, tx_id, addr)

        elif msg_type == MSG_STORE:
            self._handle_store(msg)

        elif msg_type == MSG_FIND_VALUE:
            self._handle_find_value(msg, tx_id, addr, phone)

        elif msg_type == MSG_CONNECT_REQ:
            self._handle_connect_request(msg, tx_id, addr, phone, ip, port)

        elif msg_type == MSG_RELAY:
            self._handle_relay(msg, addr, phone)

    def _handle_ping(self, tx_id: str, addr, phone: str, ip: str, port: int):
        """Reply with PONG + inject the peer's own public address as a STORE."""
        # Tell the peer what their public address looks like from outside
        pong = make_message(MSG_PONG, transactionID=tx_id)
        # Piggyback their public address in the value field so they can
        # self-announce correctly
        pong["key"]   = f"public-addr-{phone}"
        pong["value"] = f"{ip}:{port}"
        self._send(pong, addr)
        log.info(f"  → PONG to {phone} ({ip}:{port})")

        # Also proactively tell this peer about other live peers
        closest = self.registry.closest(
            node_id_from_phone(phone), k=5
        )
        # exclude self
        closest = [p for p in closest if p.phone != phone]
        if closest:
            found = make_message(
                MSG_FOUND_NODE,
                peers=[peer_to_codable(p) for p in closest]
            )
            self._send(found, addr)
            log.info(f"  → Sent {len(closest)} peers to {phone}")

    def _handle_find_node(self, msg: dict, tx_id: str, addr):
        target_bytes = msg.get("targetID") or []
        target_hex   = bytes(target_bytes).hex() if target_bytes else BOOTSTRAP_ID
        closest      = self.registry.closest(target_hex)
        reply = make_message(
            MSG_FOUND_NODE,
            transactionID=tx_id,
            peers=[peer_to_codable(p) for p in closest]
        )
        self._send(reply, addr)

    def _handle_store(self, msg: dict):
        key   = msg.get("key")
        value = msg.get("value")
        if key and value:
            self.kv.put(key, value)
            log.info(f"  STORE {key} = {value}")

    def _handle_find_value(self, msg: dict, tx_id: str, addr, phone: str):
        key = msg.get("key", "")

        # Special case: look up a peer by phone number
        # iOS stores "user-PHONE" -> "IP:PORT"
        if key.startswith("user-"):
            target_phone = key[5:]
            peer = self.registry.get(target_phone)
            if peer:
                reply = make_message(
                    MSG_FOUND_VALUE,
                    transactionID=tx_id,
                    key=key,
                    value=f"{peer.ip}:{peer.port}"
                )
                self._send(reply, addr)
                log.info(f"  FOUND_VALUE {key} = {peer.ip}:{peer.port}")
                return

        # General KV lookup
        value = self.kv.get(key)
        if value:
            reply = make_message(
                MSG_FOUND_VALUE,
                transactionID=tx_id,
                key=key,
                value=value
            )
            self._send(reply, addr)
        else:
            # Return closest peers instead
            closest = self.registry.closest(node_id_from_phone(key))
            reply = make_message(
                MSG_FOUND_NODE,
                transactionID=tx_id,
                peers=[peer_to_codable(p) for p in closest]
            )
            self._send(reply, addr)

    def _handle_connect_request(self, msg: dict, tx_id: str, addr,
                                 requester_phone: str, requester_ip: str, requester_port: int):
        """
        UDP Hole Punching coordination:
        A wants to connect to B.
        1. We find B's public address.
        2. We send A → B's address.
        3. We send B → A's address.
        Both sides then send UDP simultaneously, punching through NAT.
        """
        target_phone = msg.get("key", "")
        target_peer  = self.registry.get(target_phone)

        if not target_peer:
            log.info(f"  Hole punch: {target_phone} not found in registry")
            # Decline — target not online
            decline = make_message(MSG_CONNECT_DECLINE, transactionID=tx_id)
            self._send(decline, addr)
            return

        log.info(f"  Hole punch: {requester_phone} <-> {target_phone}")

        # Tell requester (A) about target (B)'s public address
        notify_a = make_message(
            MSG_HOLE_PUNCH,
            transactionID=tx_id,
            key=target_phone,
            value=f"{target_peer.ip}:{target_peer.port}",
        )
        self._send(notify_a, addr)

        # Tell target (B) about requester (A)'s public address
        notify_b = make_message(
            MSG_HOLE_PUNCH,
            transactionID=tx_id,
            key=requester_phone,
            value=f"{requester_ip}:{requester_port}",
        )
        self._send(notify_b, (target_peer.ip, target_peer.port))

        log.info(f"  Hole punch coords sent to both sides")

    def _handle_relay(self, msg: dict, sender_addr, sender_phone: str):
        """
        TURN-style relay fallback for symmetric NAT.

        The sender wraps its real payload inside a RELAY message:
          key   = destination phone number
          value = JSON-encoded inner KadMessage (the actual payload)

        Bootstrap unwraps it and forwards to the destination's last known
        public address, rewriting senderIP/senderPort so the receiver can
        reply back through the relay too.

        Flow:
          A  --RELAY(key=B, value=innerMsg)--> bootstrap
          bootstrap --RELAY(key=A, value=innerMsg, from A's public addr)--> B
          B  --RELAY(key=A, value=replyMsg)--> bootstrap
          bootstrap --RELAY(key=B, value=replyMsg, from B's public addr)--> A
        """
        target_phone = msg.get("key", "")
        inner_json   = msg.get("value", "")

        if not target_phone or not inner_json:
            log.warning(f"  RELAY from {sender_phone}: missing key or value")
            return

        target_peer = self.registry.get(target_phone)
        if not target_peer:
            log.info(f"  RELAY: {target_phone} not in registry, dropping")
            # Optionally tell sender the target is offline
            decline = make_message(MSG_CONNECT_DECLINE,
                                   key=target_phone,
                                   value="offline")
            self._send(decline, sender_addr)
            return

        # Validate inner payload is JSON we can decode (don't forward garbage)
        try:
            inner_msg = json.loads(inner_json)
        except Exception:
            log.warning(f"  RELAY from {sender_phone}: inner payload not valid JSON")
            return

        # Stamp the sender's real public address so the receiver knows who
        # sent it and can reply via relay using the correct source.
        inner_msg["senderIP"]   = sender_addr[0]
        inner_msg["senderPort"] = sender_addr[1]

        # Wrap in a new RELAY envelope addressed to the target
        forward = make_message(
            MSG_RELAY,
            key=sender_phone,               # so receiver knows who to reply to
            value=json.dumps(inner_msg),    # re-serialised inner message
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
            0x01: "PING", 0x02: "PONG", 0x03: "FIND_NODE",
            0x04: "FOUND_NODE", 0x05: "STORE", 0x06: "FIND_VALUE",
            0x07: "FOUND_VALUE", 0x08: "CONNECT_REQ", 0x09: "CONNECT_ACCEPT",
            0x0A: "CONNECT_DECLINE", 0x0B: "CHAT", 0x0C: "CHAT_ACK",
            0x0D: "HOLE_PUNCH", 0x0E: "RELAY",
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
    log.info(f"Bootstrap node ID: {BOOTSTRAP_ID}")

    try:
        await maintenance(protocol_instance.registry, protocol_instance.kv)
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())