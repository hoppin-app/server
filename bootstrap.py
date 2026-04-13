#!/usr/bin/env python3
"""
HopChat Bootstrap Server  —  TCP edition
=========================================
Switched from UDP to TCP so mobile carriers (carrier-grade NAT / NOS / etc.)
cannot block the traffic.  All other logic (peer registry, KV store, hole
punching, relay, SHA-256 NodeIDs) is unchanged.

Wire format — length-prefixed JSON (same as the iOS TCP transport):
    [4 bytes big-endian payload length][JSON bytes]

Each client connection carries exactly one request and one response, then
closes.  This matches the iOS sendAndWait() design.
"""

import asyncio
import json
import struct
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
MSG_PING            = 0x01
MSG_PONG            = 0x02
MSG_FIND_NODE       = 0x03
MSG_FOUND_NODE      = 0x04
MSG_STORE           = 0x05
MSG_FIND_VALUE      = 0x06
MSG_FOUND_VALUE     = 0x07
MSG_CONNECT_REQ     = 0x08
MSG_CONNECT_ACCEPT  = 0x09
MSG_CONNECT_DECLINE = 0x0A
MSG_CHAT            = 0x0B
MSG_CHAT_ACK        = 0x0C
MSG_HOLE_PUNCH      = 0x0D
MSG_RELAY           = 0x0E

K = 20


# ---------------------------------------------------------------------------
# Framing helpers
# ---------------------------------------------------------------------------

async def read_frame(reader: asyncio.StreamReader) -> Optional[bytes]:
    """Read one length-prefixed frame.  Returns None on EOF or error."""
    try:
        header = await reader.readexactly(4)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None
    length = struct.unpack(">I", header)[0]
    if length == 0 or length > 1_048_576:
        log.warning(f"Bad frame length: {length}")
        return None
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None

def make_frame(msg: dict) -> bytes:
    """Encode a message dict as a length-prefixed JSON frame."""
    payload = json.dumps(msg).encode()
    return struct.pack(">I", len(payload)) + payload


# ---------------------------------------------------------------------------
# Peer registry
# ---------------------------------------------------------------------------

@dataclass
class PeerInfo:
    node_id:   str
    phone:     str
    ip:        str
    port:      int
    last_seen: float
    lan_ip:    str = ""
    lan_port:  int = 0


class PeerRegistry:
    def __init__(self, ttl: int = 300):
        self._peers: Dict[str, PeerInfo] = {}
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
# Key-value store
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
# Node ID helpers — SHA-256 (32 bytes), matching iOS client
# ---------------------------------------------------------------------------

def node_id_from_phone(phone: str) -> str:
    return hashlib.sha256(phone.encode()).hexdigest()

def bootstrap_node_id() -> str:
    return hashlib.sha256(b"hopchat-bootstrap-server").hexdigest()

BOOTSTRAP_ID = bootstrap_node_id()


# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------

def make_message(msg_type: int, **kwargs) -> dict:
    return {
        "type":          msg_type,
        "senderID":      list(bytes.fromhex(BOOTSTRAP_ID)),  # 32 bytes
        "senderIP":      "0.0.0.0",
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
    use_lan = requester_ip and requester_ip == p.ip
    return {
        "id":    list(bytes.fromhex(p.node_id)),
        "ip":    p.lan_ip  if use_lan else p.ip,
        "port":  p.lan_port if use_lan else p.port,
        "phone": p.phone,
    }


# ---------------------------------------------------------------------------
# Bootstrap server
# ---------------------------------------------------------------------------

class BootstrapServer:
    def __init__(self):
        self.registry = PeerRegistry(ttl=300)
        self.kv       = KVStore(ttl=600)
        self._relay_count = 0

    async def handle_client(self,
                             reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        """Handle one inbound TCP connection: read one request, send one reply."""
        peer_addr = writer.get_extra_info("peername")
        ip   = peer_addr[0] if peer_addr else "0.0.0.0"
        port = peer_addr[1] if peer_addr else 0

        data = await read_frame(reader)
        if not data:
            writer.close()
            return

        try:
            msg = json.loads(data.decode())
        except Exception:
            writer.close()
            return

        phone         = msg.get("senderPhone", "unknown")
        node_id_bytes = msg.get("senderID", [])
        tx_id         = msg.get("transactionID", str(uuid.uuid4()))
        msg_type      = msg.get("type", 0)
        lan_ip        = msg.get("senderIP", ip)
        lan_port      = msg.get("senderPort", port)

        # senderID should be 32 bytes (SHA-256).
        if len(node_id_bytes) == 32:
            node_id = bytes(node_id_bytes).hex()
        else:
            node_id = node_id_from_phone(phone)
            if node_id_bytes:
                log.warning(f"[{phone}] unexpected senderID length "
                             f"{len(node_id_bytes)} — using derived SHA-256 ID")

        if phone not in ("unknown", "bootstrap"):
            self.registry.upsert(phone, node_id, ip, port, lan_ip, lan_port)
            log.info(f"[{phone}] {_type_name(msg_type)} from {ip}:{port} "
                     f"(LAN {lan_ip}:{lan_port})")

        reply = await self._dispatch(msg, msg_type, tx_id, ip, port, phone)

        if reply:
            try:
                writer.write(make_frame(reply))
                await writer.drain()
            except Exception as e:
                log.warning(f"Write error to {ip}:{port}: {e}")

        # For hole-punch we also need to notify the *target* peer on a
        # separate outbound connection (they're not the one connected to us).
        # That is handled inside _handle_connect_request via _send_to.

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def _dispatch(self, msg: dict, msg_type: int, tx_id: str,
                        ip: str, port: int, phone: str) -> Optional[dict]:
        """Route a message to the appropriate handler and return a reply dict."""

        if msg_type == MSG_PING:
            return self._handle_ping(tx_id, phone, ip, port)

        elif msg_type == MSG_FIND_NODE:
            return self._handle_find_node(msg, tx_id, ip)

        elif msg_type == MSG_STORE:
            self._handle_store(msg, public_ip=ip, public_port=port)
            return None  # STORE has no reply

        elif msg_type == MSG_FIND_VALUE:
            return self._handle_find_value(msg, tx_id, phone, ip)

        elif msg_type == MSG_CONNECT_REQ:
            return await self._handle_connect_request(
                msg, tx_id, phone, ip, port)

        elif msg_type == MSG_RELAY:
            await self._handle_relay(msg, phone, ip, port)
            return None

        return None

    # -----------------------------------------------------------------------
    # Handlers
    # -----------------------------------------------------------------------

    def _handle_ping(self, tx_id: str, phone: str, ip: str, port: int) -> dict:
        pong = make_message(MSG_PONG, transactionID=tx_id)
        pong["key"]   = f"public-addr-{phone}"
        pong["value"] = f"{ip}:{port}"
        log.info(f"  → PONG to {phone} ({ip}:{port})")

        # We can only send ONE reply on this connection, so we cannot also
        # push a FOUND_NODE with nearby peers here.  The client's bootstrap()
        # will do a FIND_NODE immediately after the PING, which achieves the
        # same effect.
        return pong

    def _handle_find_node(self, msg: dict, tx_id: str, requester_ip: str) -> dict:
        target_bytes = msg.get("targetID") or []
        target_hex   = bytes(target_bytes).hex() if target_bytes else BOOTSTRAP_ID
        closest      = self.registry.closest(target_hex)
        reply = make_message(
            MSG_FOUND_NODE,
            transactionID=tx_id,
            peers=[peer_to_codable(p, requester_ip=requester_ip) for p in closest]
        )
        log.info(f"  → FOUND_NODE: {len(closest)} peers")
        return reply

    def _handle_store(self, msg: dict,
                      public_ip: str = None, public_port: int = None):
        key   = msg.get("key")
        value = msg.get("value")
        if not (key and value):
            return
        if key.startswith("user-") and public_ip:
            corrected = f"{public_ip}:{public_port}"
            if value != corrected:
                log.info(f"  STORE {key}: client said {value}, "
                         f"overriding with {corrected}")
            self.kv.put(key, corrected)
        else:
            self.kv.put(key, value)
        log.info(f"  STORE {key} = {self.kv.get(key)}")

    def _handle_find_value(self, msg: dict, tx_id: str,
                            phone: str, requester_ip: str) -> dict:
        key = msg.get("key", "")

        if key.startswith("user-"):
            target_phone = key[5:]
            peer = self.registry.get(target_phone)
            if peer:
                requester_peer = self.registry.get(phone)
                if requester_peer and requester_peer.ip == peer.ip:
                    addr = f"{peer.lan_ip}:{peer.lan_port}"
                    log.info(f"  → Same NAT, returning LAN addr: {addr}")
                else:
                    addr = f"{peer.ip}:{peer.port}"
                log.info(f"  FOUND_VALUE {key} = {addr}")
                return make_message(MSG_FOUND_VALUE, transactionID=tx_id,
                                    key=key, value=addr)

        value = self.kv.get(key)
        if value:
            return make_message(MSG_FOUND_VALUE, transactionID=tx_id,
                                key=key, value=value)

        closest = self.registry.closest(node_id_from_phone(key))
        return make_message(
            MSG_FOUND_NODE,
            transactionID=tx_id,
            peers=[peer_to_codable(p, requester_ip=requester_ip) for p in closest]
        )

    async def _handle_connect_request(self, msg: dict, tx_id: str,
                                       requester_phone: str,
                                       requester_ip: str,
                                       requester_port: int) -> dict:
        """
        Hole-punch coordination.
        Reply to the requester AND send an unsolicited HOLE_PUNCH to the target
        on a separate outbound TCP connection.
        """
        target_phone = msg.get("key", "")
        target_peer  = self.registry.get(target_phone)

        if not target_peer:
            log.info(f"  Hole punch: {target_phone} not found")
            return make_message(MSG_CONNECT_DECLINE, transactionID=tx_id)

        log.info(f"  Hole punch: {requester_phone} ({requester_ip}:{requester_port})"
                 f" <-> {target_phone} ({target_peer.ip}:{target_peer.port})")

        # Notify target (B) where requester (A) is — outbound connection.
        notify_b = make_message(
            MSG_HOLE_PUNCH,
            transactionID=tx_id,
            key=requester_phone,
            value=f"{requester_ip}:{requester_port}",
        )
        asyncio.create_task(
            self._send_to(notify_b, target_peer.ip, target_peer.port)
        )

        # Reply to requester (A) with target (B)'s address.
        return make_message(
            MSG_HOLE_PUNCH,
            transactionID=tx_id,
            key=target_phone,
            value=f"{target_peer.ip}:{target_peer.port}",
        )

    async def _handle_relay(self, msg: dict,
                             sender_phone: str,
                             sender_ip: str, sender_port: int):
        target_phone = msg.get("key", "")
        inner_json   = msg.get("value", "")

        if not target_phone or not inner_json:
            log.warning(f"  RELAY from {sender_phone}: missing key/value")
            return

        target_peer = self.registry.get(target_phone)
        if not target_peer:
            log.info(f"  RELAY: {target_phone} not in registry")
            return

        try:
            inner_msg = json.loads(inner_json)
        except Exception:
            log.warning(f"  RELAY from {sender_phone}: inner payload not JSON")
            return

        inner_msg["senderIP"]   = sender_ip
        inner_msg["senderPort"] = sender_port

        forward = make_message(
            MSG_RELAY,
            key=sender_phone,
            value=json.dumps(inner_msg),
        )
        await self._send_to(forward, target_peer.ip, target_peer.port)

        self._relay_count += 1
        log.debug(f"  RELAY {sender_phone} -> {target_phone}")

    async def _send_to(self, msg: dict, ip: str, port: int):
        """Open an outbound TCP connection and send a single framed message."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5.0
            )
            writer.write(make_frame(msg))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            log.debug(f"  → Pushed type={msg['type']} to {ip}:{port}")
        except Exception as e:
            log.warning(f"  _send_to {ip}:{port} failed: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

async def maintenance(server: BootstrapServer, interval: int = 60):
    while True:
        await asyncio.sleep(interval)
        server.registry.evict_stale()
        server.kv.evict_stale()
        live = server.registry.all_live()
        log.info(f"[maintenance] {len(live)} live peers")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    server = BootstrapServer()

    tcp_server = await asyncio.start_server(
        server.handle_client,
        host="0.0.0.0",
        port=PORT,
    )

    log.info(f"HopChat bootstrap server (TCP) started on port {PORT}")
    log.info(f"Bootstrap node ID (SHA-256): {BOOTSTRAP_ID}")

    async with tcp_server:
        await asyncio.gather(
            tcp_server.serve_forever(),
            maintenance(server),
        )


if __name__ == "__main__":
    asyncio.run(main())