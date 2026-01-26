# MX Record Auto-Discovery for Cluster Definitions

**Date:** 2026-01-26
**Status:** Approved
**Author:** Brainstorming session

## Overview

Add MX record auto-discovery to mailtrace cluster configuration, aligning with Postfix's behavior when `relayhost` is specified without brackets (triggering MX lookup).

## Motivation

When Postfix uses `relayhost = example.com` (no brackets), it queries MX records for that domain and routes mail to those servers. Users want mailtrace's cluster configuration to match this pattern for consistency between mail routing and mail tracing.

## Configuration

### New `mx_discovery` Section

```yaml
mx_discovery:
  servers: []        # Custom DNS servers (empty = system resolver)
  timeout: 5         # Query timeout in seconds (default: 5)
  cache_ttl: 0       # Cache TTL in seconds (0 = no cache, default: 0)
```

### Cluster Syntax with `mx:` Prefix

```yaml
clusters:
  # Pure static cluster (unchanged, backward compatible)
  legacy-cluster:
    - host1.example.com
    - host2.example.com

  # Pure MX-based cluster
  mx-relay:
    - "mx:example.com"

  # Mixed: MX + static hosts merged
  hybrid-cluster:
    - "mx:primary.example.com"
    - backup-relay.other.com
    - "mx:secondary.example.com"
```

### Configuration Defaults

When `mx_discovery` section is omitted:
- `servers`: System resolver (empty list)
- `timeout`: 5 seconds
- `cache_ttl`: 0 (no caching, always fresh query)

## Behavior

### MX Entry Expansion

1. Entries starting with `mx:` trigger DNS MX lookup for the domain portion
2. All resolved MX hostnames are merged with static entries
3. Duplicates are removed after merging
4. Resolved hostnames go through existing `get_hosts()` expansion for consistency

### MX Priority Handling

All MX hosts are included regardless of priority. Mailtrace queries all hosts in a cluster anyway, so priority ordering is not relevant.

### Error Handling

On DNS failure (timeout, NXDOMAIN, no MX records):
- Log a warning with the failure reason
- Exclude that `mx:` entry from the cluster
- Continue with remaining hosts (if any)

```
WARNING: MX lookup failed for example.com: DNS timeout after 5s
WARNING: MX lookup failed for invalid.test: NXDOMAIN
WARNING: No MX records found for example.org
```

### Caching

- `cache_ttl: 0` (default): Always perform fresh DNS query
- `cache_ttl: N` (N > 0): Cache results for N seconds

## Implementation

### New Dependency

Add to `pyproject.toml`:

```toml
[project]
dependencies = [
    # ... existing deps
    "dnspython>=2.4.0",
]
```

### New Module: `mailtrace/mx_discovery.py`

```python
import dns.resolver
from dataclasses import dataclass
import logging
import time

logger = logging.getLogger(__name__)

@dataclass
class MXDiscoveryConfig:
    servers: list[str]  # Empty = system resolver
    timeout: int = 5
    cache_ttl: int = 0  # 0 = no cache

class MXDiscovery:
    def __init__(self, config: MXDiscoveryConfig):
        self.config = config
        self._cache: dict[str, tuple[list[str], float]] = {}

    def resolve(self, domain: str) -> list[str]:
        """Resolve MX records for domain, return list of hostnames."""
        # Check cache if cache_ttl > 0
        if self.config.cache_ttl > 0:
            cached = self._cache.get(domain)
            if cached:
                hosts, timestamp = cached
                if time.time() - timestamp < self.config.cache_ttl:
                    return hosts

        # Configure resolver
        resolver = dns.resolver.Resolver()
        if self.config.servers:
            resolver.nameservers = self.config.servers
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout

        try:
            answers = resolver.resolve(domain, 'MX')
            hosts = [str(rdata.exchange).rstrip('.') for rdata in answers]

            # Cache result if caching enabled
            if self.config.cache_ttl > 0:
                self._cache[domain] = (hosts, time.time())

            return hosts
        except dns.resolver.Timeout:
            logger.warning(f"MX lookup failed for {domain}: DNS timeout after {self.config.timeout}s")
            return []
        except dns.resolver.NXDOMAIN:
            logger.warning(f"MX lookup failed for {domain}: NXDOMAIN")
            return []
        except dns.resolver.NoAnswer:
            logger.warning(f"No MX records found for {domain}")
            return []
        except Exception as e:
            logger.warning(f"MX lookup failed for {domain}: {e}")
            return []

    def expand_entry(self, entry: str) -> list[str]:
        """If entry starts with 'mx:', resolve it. Otherwise return as-is."""
        if entry.startswith("mx:"):
            domain = entry[3:]
            return self.resolve(domain)
        return [entry]
```

### Config Changes: `mailtrace/config.py`

Add `MXDiscoveryConfig` dataclass:

```python
@dataclass
class MXDiscoveryConfig:
    servers: list[str] = field(default_factory=list)
    timeout: int = 5
    cache_ttl: int = 0
```

Add to `Config` dataclass:

```python
@dataclass
class Config:
    # ... existing fields
    mx_discovery: MXDiscoveryConfig = field(default_factory=MXDiscoveryConfig)
    _mx_resolver: MXDiscovery | None = field(default=None, repr=False)

    def __post_init__(self):
        from .mx_discovery import MXDiscovery
        self._mx_resolver = MXDiscovery(self.mx_discovery)

    def cluster_to_hosts(self, name: str) -> list[str] | None:
        """Get list of hosts for a given cluster name, expanding mx: entries."""
        raw_entries = self.clusters.get(name)
        if raw_entries is None:
            return None

        # Expand mx: entries and merge
        hosts = []
        for entry in raw_entries:
            hosts.extend(self._mx_resolver.expand_entry(entry))

        # Apply existing get_hosts() expansion, deduplicate
        return list(dict.fromkeys(get_hosts(hosts, self.domain)))
```

## Testing

### Unit Tests: `tests/test_mx_discovery.py`

```python
def test_expand_static_entry():
    """Non-mx: entries pass through unchanged."""

def test_expand_mx_entry_success(mock_dns):
    """mx:example.com resolves to MX hostnames."""

def test_expand_mx_entry_timeout(mock_dns):
    """Timeout logs warning, returns empty list."""

def test_expand_mx_entry_nxdomain(mock_dns):
    """NXDOMAIN logs warning, returns empty list."""

def test_expand_mx_entry_no_records(mock_dns):
    """No MX records logs warning, returns empty list."""

def test_cache_disabled():
    """cache_ttl=0 always queries DNS."""

def test_cache_enabled(mock_dns):
    """cache_ttl>0 returns cached result within TTL."""

def test_cache_expired(mock_dns):
    """Expired cache triggers fresh DNS query."""

def test_custom_dns_servers(mock_dns):
    """Custom servers are used instead of system resolver."""

def test_mixed_cluster_expansion():
    """Cluster with mx: and static entries merges correctly."""
```

### Mocking Approach

- Use `unittest.mock.patch` on `dns.resolver.Resolver.resolve`
- Test both success and failure scenarios
- No real DNS queries in unit tests

## File Changes Summary

| File | Change |
|------|--------|
| `pyproject.toml` | Add `dnspython>=2.4.0` dependency |
| `mailtrace/mx_discovery.py` | New module with `MXDiscovery` class |
| `mailtrace/config.py` | Add `MXDiscoveryConfig` dataclass, update `cluster_to_hosts()` |
| `tests/test_mx_discovery.py` | Unit tests with mocked DNS |

## Backward Compatibility

Fully backward compatible:
- Existing static cluster definitions work unchanged
- `mx_discovery` section is optional with sensible defaults
- Mixed clusters allow gradual migration
