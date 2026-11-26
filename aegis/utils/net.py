"""CIDR / IP helpers (no external deps)."""

import ipaddress


def parse_cidr(cidr: str) -> ipaddress._BaseNetwork:
    return ipaddress.ip_network(cidr, strict=False)


def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if *ip* (or *cidr* itself) is contained in *cidr*."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr in ipaddress.ip_network(cidr, strict=False)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
