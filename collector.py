from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx

LOGGER = logging.getLogger(__name__)

SUPPORTED_SCHEMES = {
    "vmess",
    "vless",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "hy2",
}

NAME_KEYS = {"ps", "name", "remark", "remarks", "group"}
HOSTLIKE_QUERY_KEYS = {"host", "sni", "peer", "servername", "authority"}
BOOL_QUERY_KEYS = {"insecure", "allowinsecure"}


@dataclass(slots=True)
class CollectorSettings:
    source_list_path: Path = Path("collectors.txt")
    fetch_timeout_seconds: float = 20.0
    merged_output_path: Path = Path("collection-of-collector.txt")


def _canonical_scheme(scheme: str) -> str:
    scheme_lower = scheme.lower()
    if scheme_lower == "hy2":
        return "hysteria2"
    return scheme_lower


def _pad_b64(raw: str) -> str:
    clean = "".join(raw.split())
    padding = len(clean) % 4
    if padding:
        clean += "=" * (4 - padding)
    return clean


def _b64_decode(raw: str) -> str:
    padded = _pad_b64(raw)
    for altchars in (None, b"-_"):
        try:
            payload = base64.b64decode(
                padded if altchars is None else padded.encode("utf-8"),
                altchars=altchars,
                validate=False,
            )
            return payload.decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            continue
    raise ValueError("Invalid base64 content")


def _is_config_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or "://" not in stripped:
        return False
    scheme = stripped.split("://", 1)[0].strip().lower()
    return _canonical_scheme(scheme) in SUPPORTED_SCHEMES


def _extract_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if _is_config_line(line)]


def _extract_subscription_configs(raw_text: str) -> list[str]:
    direct_lines = _extract_lines(raw_text)
    if direct_lines:
        return direct_lines

    try:
        decoded = _b64_decode(raw_text)
    except ValueError:
        return []
    return _extract_lines(decoded)


def _atomic_write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(lines)
    if payload:
        payload += "\n"

    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)

    os.replace(tmp_path, path)


def _normalize_path(path: str) -> str:
    if not path:
        return ""
    decoded = unquote(path)
    return decoded


def _normalize_query_pairs(pairs: list[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    normalized: list[tuple[str, str]] = []
    for key, value in pairs:
        key_norm = key.strip().lower()
        if key_norm in NAME_KEYS:
            continue

        value_norm = value.strip()
        if key_norm in HOSTLIKE_QUERY_KEYS:
            value_norm = value_norm.lower()
        if key_norm in BOOL_QUERY_KEYS:
            lowered = value_norm.lower()
            if lowered in {"1", "true", "yes", "on"}:
                value_norm = "true"
            elif lowered in {"0", "false", "no", "off"}:
                value_norm = "false"

        normalized.append((key_norm, value_norm))

    normalized.sort()
    return tuple(normalized)


def _host_port_fallback(parsed: Any) -> tuple[str, int]:
    host = (parsed.hostname or "").strip().lower()
    port = parsed.port or 0
    return host, int(port)


def _fingerprint_vmess(line: str) -> str:
    content = line.split("://", 1)[1].split("#", 1)[0].strip()
    decoded = _b64_decode(content)
    data = json.loads(decoded)

    normalized: dict[str, Any] = {}
    for key, value in data.items():
        key_norm = key.strip().lower()
        if key_norm in NAME_KEYS:
            continue
        if value is None:
            continue

        if key_norm in {"add", "host", "sni"}:
            normalized[key_norm] = str(value).strip().lower()
        elif key_norm in {"port", "aid", "alterid"}:
            try:
                normalized[key_norm] = int(str(value))
            except ValueError:
                normalized[key_norm] = str(value).strip()
        elif key_norm in {"tls", "security", "net", "type", "path", "alpn", "fp", "flow", "scy"}:
            normalized[key_norm] = str(value).strip().lower()
        else:
            normalized[key_norm] = str(value).strip()

    fingerprint_body = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return "vmess:" + hashlib.sha256(fingerprint_body.encode("utf-8")).hexdigest()


def _decode_ss_userinfo(token: str) -> tuple[str, str]:
    if ":" in token:
        method, password = token.split(":", 1)
        return unquote(method), unquote(password)

    decoded = _b64_decode(token)
    if ":" not in decoded:
        raise ValueError("Invalid ss credential format")
    method, password = decoded.split(":", 1)
    return method, password


def _fingerprint_ss(line: str) -> str:
    body = line.split("://", 1)[1].split("#", 1)[0]
    if "?" in body:
        body_main, query_str = body.split("?", 1)
    else:
        body_main, query_str = body, ""

    if "@" in body_main:
        userinfo, hostport = body_main.rsplit("@", 1)
    else:
        decoded = _b64_decode(body_main)
        if "@" not in decoded:
            raise ValueError("Invalid ss URI")
        userinfo, hostport = decoded.rsplit("@", 1)

    method, password = _decode_ss_userinfo(userinfo)
    parsed_host = urlsplit(f"ss://dummy@{hostport}")
    host = (parsed_host.hostname or "").lower()
    port = parsed_host.port or 0

    query = _normalize_query_pairs(parse_qsl(query_str, keep_blank_values=True))
    payload = {
        "method": method,
        "password": password,
        "host": host,
        "port": port,
        "query": query,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "ss:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _decode_ssr_param(value: str) -> str:
    if not value:
        return ""
    try:
        return _b64_decode(value)
    except ValueError:
        return value


def _fingerprint_ssr(line: str) -> str:
    body = line.split("://", 1)[1].split("#", 1)[0].strip()
    decoded = _b64_decode(body)
    main, _, query_str = decoded.partition("/?")

    fields = main.split(":")
    if len(fields) < 6:
        raise ValueError("Invalid ssr main section")

    host, port, protocol, method, obfs, password_b64 = fields[:6]
    password = _decode_ssr_param(password_b64)

    query_pairs = parse_qsl(query_str, keep_blank_values=True)
    query_norm: list[tuple[str, str]] = []
    for key, value in query_pairs:
        key_norm = key.lower()
        if key_norm in {"remarks", "group"}:
            continue
        query_norm.append((key_norm, _decode_ssr_param(value)))
    query_norm.sort()

    payload = {
        "host": host.lower(),
        "port": int(port),
        "protocol": protocol.lower(),
        "method": method,
        "obfs": obfs.lower(),
        "password": password,
        "query": query_norm,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "ssr:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _fingerprint_common_url(line: str) -> str:
    base = line.strip()
    parsed = urlsplit(base)
    scheme = _canonical_scheme(parsed.scheme)
    host, port = _host_port_fallback(parsed)

    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    path = _normalize_path(parsed.path)
    query = _normalize_query_pairs(parse_qsl(parsed.query, keep_blank_values=True))

    payload = {
        "scheme": scheme,
        "user": user,
        "password": password,
        "host": host,
        "port": port,
        "path": path,
        "query": query,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return scheme + ":" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _fingerprint(line: str) -> str | None:
    stripped = line.strip()
    if not _is_config_line(stripped):
        return None

    scheme = _canonical_scheme(stripped.split("://", 1)[0])
    try:
        if scheme == "vmess":
            return _fingerprint_vmess(stripped)
        if scheme == "ss":
            return _fingerprint_ss(stripped)
        if scheme == "ssr":
            return _fingerprint_ssr(stripped)
        return _fingerprint_common_url(stripped)
    except Exception:
        # If parsing fails, keep deterministic fallback fingerprint without remark.
        no_fragment = stripped.split("#", 1)[0]
        fallback = no_fragment.encode("utf-8", errors="replace")
        return scheme + ":fallback:" + hashlib.sha256(fallback).hexdigest()


def deduplicate_config_lines(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []

    for line in lines:
        fingerprint = _fingerprint(line)
        if fingerprint is None or fingerprint in seen:
            continue
        seen.add(fingerprint)
        output.append(line.strip())

    return output


async def _fetch_one(client: httpx.AsyncClient, url: str) -> list[str]:
    try:
        response = await client.get(url)
        response.raise_for_status()
    except Exception as exc:
        LOGGER.warning("Failed to fetch %s: %s", url, exc)
        return []

    return _extract_subscription_configs(response.text)


def _load_sources(path: Path) -> list[str]:
    if not path.exists():
        return []

    urls: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


async def collect_and_dedup(settings: CollectorSettings) -> list[str]:
    urls = _load_sources(settings.source_list_path)
    if not urls:
        LOGGER.warning("No collector source URLs found in %s", settings.source_list_path)
        _atomic_write_lines(settings.merged_output_path, [])
        return []

    timeout = httpx.Timeout(settings.fetch_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        results = await asyncio.gather(*(_fetch_one(client, url) for url in urls))

    merged: list[str] = []
    for result in results:
        merged.extend(result)

    deduped = deduplicate_config_lines(merged)
    _atomic_write_lines(settings.merged_output_path, deduped)

    LOGGER.info(
        "Collection finished: sources=%d merged=%d deduped=%d",
        len(urls),
        len(merged),
        len(deduped),
    )
    return deduped
