"""Immutable controller launch inputs shared by Docker execution boundaries."""
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import stat


def sealed_bytes(path: Path, *, expected: str | None = None, limit: int = 1024 * 1024) -> bytes:
    """Read the controller's sealed input without following a replacement link."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("Docker launch input path is not canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400):
            raise ValueError("Docker launch input is not a sealed owned file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(limit + 1)
        if len(raw) > limit or expected is not None and sha256(raw).hexdigest() != expected:
            raise ValueError("Docker launch input digest/size changed")
        return raw
    finally:
        os.close(descriptor)


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def network_arguments(packet: dict) -> list[str]:
    """Validate the sealed dedicated bridge and compile its fixed worker flags."""
    if "network" not in packet:
        if packet.get("network_id") != "none" or "worker_authority" in packet:
            raise ValueError("selected Docker bridge settings are required")
        return []
    network = packet["network"]
    if (not isinstance(network, dict) or set(network) != {
            "worker_ipv4", "controller_ipv4", "subnet", "gateway", "bridge_name", "dns"} or
            not isinstance(packet.get("network_id"), str) or
            not re.fullmatch("[0-9a-f]{64}", packet["network_id"]) or
            any(not isinstance(network[key], str) for key in
                ("worker_ipv4", "controller_ipv4", "subnet", "gateway", "bridge_name"))):
        raise ValueError("invalid Docker bridge descriptor")
    subnet = ipaddress.IPv4Network(network["subnet"])
    addresses = [ipaddress.IPv4Address(network[key]) for key in ("worker_ipv4", "controller_ipv4", "gateway")]
    if (str(subnet) != network["subnet"] or not any(subnet.subnet_of(ipaddress.IPv4Network(private))
            for private in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")) or
            len(set(addresses)) != 3 or any(address not in subnet or
                address in {subnet.network_address, subnet.broadcast_address} for address in addresses) or
            any(str(address) != network[key] for key, address in zip(
                ("worker_ipv4", "controller_ipv4", "gateway"), addresses)) or
            not isinstance(network["bridge_name"], str) or
            not re.fullmatch(r"br-[A-Za-z0-9_-]{1,12}", network["bridge_name"])):
        raise ValueError("invalid Docker bridge addresses or interface")
    dns = network["dns"]
    if (not isinstance(dns, list) or not 1 <= len(dns) <= 3 or
            any(not isinstance(value, str) for value in dns) or len(set(dns)) != len(dns)):
        raise ValueError("invalid Docker public DNS selection")
    for value in dns:
        address = ipaddress.IPv4Address(value)
        if str(address) != value or not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError("Docker DNS must use canonical public IPv4 addresses")
    return ["--ip", network["worker_ipv4"], *[part for value in dns for part in ("--dns", value)],
        "--sysctl", "net.ipv6.conf.all.disable_ipv6=1"]
