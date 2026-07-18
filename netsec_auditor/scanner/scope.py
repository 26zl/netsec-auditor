"""Authorization and scope validation — ensures scanning is only performed on authorized targets."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class ScopeError(Exception):
    """Raised when a target falls outside the authorized scope."""


@dataclass
class Scope:
    """Defines the authorized scanning scope."""

    name: str
    description: str = ""
    cidr_ranges: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    excluded_cidr_ranges: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    excluded_ip_addresses: list[str] = field(default_factory=list)
    allowed_ports: list[int] | None = None
    max_scan_rate: int = 100
    authorized_by: str = ""
    authorization_date: str = ""
    authorization_ref: str = ""

    _parsed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list, init=False, repr=False
    )
    _parsed_excluded_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list, init=False, repr=False
    )
    _parsed_ips: set[str] = field(default_factory=set, init=False, repr=False)
    _parsed_excluded_ips: set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        for cidr in self.cidr_ranges:
            self._parsed_cidrs.append(ipaddress.ip_network(cidr, strict=False))
        for cidr in self.excluded_cidr_ranges:
            self._parsed_excluded_cidrs.append(ipaddress.ip_network(cidr, strict=False))
        self._parsed_ips = set(self.ip_addresses)
        self._parsed_excluded_ips = set(self.excluded_ip_addresses)

    def validate_target(self, target: str) -> bool:
        """Check if a target is within authorized scope. Raises ScopeError if not.

        Accepts bare IPs, hostnames, full URLs, and CIDR ranges.
        """
        host = self._extract_host(target)

        if "/" in host:
            return self._validate_network(host, target)

        ip = self._resolve_to_ip(host)

        for excluded_cidr in self._parsed_excluded_cidrs:
            if ip in excluded_cidr:
                raise ScopeError(f"Target {target} ({ip}) is in excluded range {excluded_cidr}")

        if str(ip) in self._parsed_excluded_ips:
            raise ScopeError(f"Target {target} ({ip}) is explicitly excluded")

        if self._domain_matches(host, self.excluded_domains):
            raise ScopeError(f"Target {target} is an explicitly excluded domain")

        for cidr in self._parsed_cidrs:
            if ip in cidr:
                return True

        if str(ip) in self._parsed_ips:
            return True

        if self._domain_matches(host, self.domains):
            return True

        raise ScopeError(
            f"Target {target} ({ip}) is NOT in authorized scope. "
            f"Authorized ranges: {self.cidr_ranges}, domains: {self.domains}"
        )

    def _validate_network(self, network_str: str, target: str) -> bool:
        """Validate a CIDR target: authorized only if fully contained in an in-scope range."""
        try:
            network = ipaddress.ip_network(network_str, strict=False)
        except ValueError:
            raise ScopeError(f"Invalid target range: {target}") from None

        for excluded in self._parsed_excluded_cidrs:
            try:
                if network.overlaps(excluded):
                    raise ScopeError(f"Target range {target} overlaps excluded range {excluded}")
            except TypeError:
                continue

        for cidr in self._parsed_cidrs:
            if self._subnet_of(network, cidr):
                return True

        raise ScopeError(
            f"Target range {target} is NOT within authorized scope. "
            f"Authorized ranges: {self.cidr_ranges}"
        )

    @staticmethod
    def _subnet_of(
        network: IPv4Network | IPv6Network, cidr: IPv4Network | IPv6Network
    ) -> bool:
        """True if ``network`` is a subnet of ``cidr``; mixed IP versions never match."""
        if isinstance(network, IPv4Network) and isinstance(cidr, IPv4Network):
            return network.subnet_of(cidr)
        if isinstance(network, IPv6Network) and isinstance(cidr, IPv6Network):
            return network.subnet_of(cidr)
        return False

    def validate_port(self, port: int) -> bool:
        """Check if a port is within allowed range."""
        if self.allowed_ports is None:
            return True
        if port in self.allowed_ports:
            return True
        raise ScopeError(f"Port {port} is not in allowed ports: {self.allowed_ports}")

    @staticmethod
    def _extract_host(target: str) -> str:
        """Strip URL scheme/path, returning the bare host (or network) string."""
        target = target.strip()
        if "://" in target:
            return urlparse(target).hostname or target
        return target

    @staticmethod
    def _domain_matches(host: str, patterns: list[str]) -> bool:
        """Match a host against domain patterns, supporting '*.example.com' wildcards."""
        host = host.lower()
        for pattern in patterns:
            pattern = pattern.lower()
            if pattern == host:
                return True
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return True
        return False

    @staticmethod
    def _resolve_to_ip(target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Resolve a host string to an IP address."""
        target = target.strip()
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            pass

        try:
            resolved = socket.getaddrinfo(target, None)[0][4][0]
            return ipaddress.ip_address(resolved)
        except (socket.gaierror, IndexError):
            raise ScopeError(f"Cannot resolve target: {target}") from None

    @classmethod
    def from_yaml(cls, path: Path) -> Scope:
        """Load scope definition from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "cidr_ranges": self.cidr_ranges,
            "domains": self.domains,
            "ip_addresses": self.ip_addresses,
            "excluded_cidr_ranges": self.excluded_cidr_ranges,
            "excluded_domains": self.excluded_domains,
            "excluded_ip_addresses": self.excluded_ip_addresses,
            "allowed_ports": self.allowed_ports,
            "max_scan_rate": self.max_scan_rate,
            "authorized_by": self.authorized_by,
            "authorization_date": self.authorization_date,
            "authorization_ref": self.authorization_ref,
        }


class ScopeManager:
    """Manages multiple scopes for different engagements."""

    def __init__(self) -> None:
        self._scopes: dict[str, Scope] = {}

    def load_scope(self, path: Path) -> Scope:
        scope = Scope.from_yaml(path)
        self._scopes[scope.name] = scope
        return scope

    def get_scope(self, name: str) -> Scope | None:
        return self._scopes.get(name)

    def list_scopes(self) -> list[str]:
        return list(self._scopes.keys())
