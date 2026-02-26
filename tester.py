from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
import signal
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class TesterSettings:
    xray_bin: str = "xray"
    batch_size: int = 25
    request_timeout_seconds: float = 15.0
    batch_timeout_seconds: float = 0.0
    startup_wait_seconds: float = 8.0
    port_start: int = 20000
    working_output_path: Path = Path("collection-of-collectors-working.txt")
    pass_url: str = "https://www.google.com/generate_204"
    max_configs_per_cycle: int = 0


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


def _atomic_write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(lines)
    if payload:
        payload += "\n"

    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)

    os.replace(tmp_path, path)


def _normalize_security(value: str | None) -> str:
    if not value:
        return "none"
    return value.strip().lower()


def _parse_stream_settings(query: dict[str, str], default_host: str) -> dict:
    net = (query.get("type") or query.get("net") or "tcp").lower()
    stream: dict = {"network": net}

    security = _normalize_security(query.get("security") or query.get("tls"))
    if security in {"tls", "reality"}:
        stream["security"] = security
        tls_settings: dict = {}

        server_name = query.get("sni") or query.get("host") or default_host
        if server_name:
            tls_settings["serverName"] = server_name

        alpn = query.get("alpn")
        if alpn:
            tls_settings["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]

        insecure_raw = (query.get("insecure") or query.get("allowInsecure") or "0").lower()
        tls_settings["allowInsecure"] = insecure_raw in {"1", "true", "yes", "on"}
        stream["tlsSettings"] = tls_settings

    path = query.get("path") or ""
    host_header = query.get("host") or default_host

    if net == "ws":
        ws_settings: dict = {"path": path or "/"}
        if host_header:
            ws_settings["headers"] = {"Host": host_header}
        stream["wsSettings"] = ws_settings
    elif net == "grpc":
        service_name = query.get("serviceName") or query.get("service_name") or path.strip("/")
        stream["grpcSettings"] = {"serviceName": service_name or "grpc"}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path or "/"}
    elif net == "xhttp":
        stream["xhttpSettings"] = {"path": path or "/"}
    elif net == "splithttp":
        stream["splithttpSettings"] = {"path": path or "/"}

    return stream


def _vmess_outbound(line: str) -> dict:
    encoded = line.split("://", 1)[1].split("#", 1)[0].strip()
    data = json.loads(_b64_decode(encoded))

    host = str(data.get("add", "")).strip()
    if not host:
        raise ValueError("vmess missing host")

    port = int(str(data.get("port", "0")))
    if port <= 0:
        raise ValueError("vmess invalid port")

    uid = str(data.get("id", "")).strip()
    if not uid:
        raise ValueError("vmess missing id")

    aid_value = data.get("aid") or data.get("alterId") or 0
    try:
        alter_id = int(str(aid_value))
    except ValueError:
        alter_id = 0

    user = {
        "id": uid,
        "alterId": max(0, alter_id),
        "security": str(data.get("scy", "auto")).strip() or "auto",
    }

    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [user],
                }
            ]
        },
    }

    query = {
        "type": str(data.get("net", "tcp")),
        "security": str(data.get("tls", "none")),
        "path": str(data.get("path", "")),
        "host": str(data.get("host", "")),
        "sni": str(data.get("sni", "")),
        "alpn": str(data.get("alpn", "")),
        "fp": str(data.get("fp", "")),
    }
    stream = _parse_stream_settings(query, host)
    outbound["streamSettings"] = stream
    return outbound


def _vless_outbound(parsed, query: dict[str, str]) -> dict:
    host = parsed.hostname or ""
    port = parsed.port or 0
    uid = unquote(parsed.username or "")
    if not host or port <= 0 or not uid:
        raise ValueError("Invalid vless URI")

    user = {"id": uid, "encryption": query.get("encryption", "none")}
    flow = query.get("flow")
    if flow:
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": _parse_stream_settings(query, host),
    }
    return outbound


def _trojan_outbound(parsed, query: dict[str, str]) -> dict:
    host = parsed.hostname or ""
    port = parsed.port or 0
    password = unquote(parsed.username or "")
    if not host or port <= 0 or not password:
        raise ValueError("Invalid trojan URI")

    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": host,
                    "port": port,
                    "password": password,
                }
            ]
        },
        "streamSettings": _parse_stream_settings(query, host),
    }
    return outbound


def _decode_ss_userinfo(token: str) -> tuple[str, str]:
    if ":" in token:
        method, password = token.split(":", 1)
        return unquote(method), unquote(password)

    decoded = _b64_decode(token)
    if ":" not in decoded:
        raise ValueError("Invalid ss credential format")
    method, password = decoded.split(":", 1)
    return method, password


def _ss_outbound(line: str) -> dict:
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
    parsed = urlsplit(f"ss://dummy@{hostport}")
    host = parsed.hostname or ""
    port = parsed.port or 0
    if not host or port <= 0:
        raise ValueError("Invalid ss host/port")

    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password,
                }
            ]
        },
    }

    query = dict(parse_qsl(query_str, keep_blank_values=True))
    plugin = query.get("plugin")
    if plugin:
        outbound["settings"]["servers"][0]["plugin"] = plugin

    return outbound


def _hysteria2_outbound(parsed, query: dict[str, str]) -> dict:
    host = parsed.hostname or ""
    port = parsed.port or 0
    password = unquote(parsed.username or "")
    if not host or port <= 0:
        raise ValueError("Invalid hysteria2 URI")

    server: dict = {
        "address": host,
        "port": port,
    }
    if password:
        server["password"] = password

    sni = query.get("sni") or query.get("serverName")
    if sni:
        server["sni"] = sni

    insecure_raw = (query.get("insecure") or "0").lower()
    if insecure_raw in {"1", "true", "yes", "on"}:
        server["insecure"] = True

    obfs = query.get("obfs")
    if obfs:
        server["obfs"] = {"type": obfs}
        obfs_password = query.get("obfs-password") or query.get("obfsPassword")
        if obfs_password:
            server["obfs"]["password"] = obfs_password

    return {
        "protocol": "hysteria2",
        "settings": {
            "servers": [server],
        },
    }


def build_xray_outbound(line: str) -> dict | None:
    raw = line.strip()
    if not raw or "://" not in raw:
        return None

    scheme = raw.split("://", 1)[0].strip().lower()
    if scheme == "hy2":
        scheme = "hysteria2"

    if scheme == "vmess":
        return _vmess_outbound(raw)

    parsed = urlsplit(raw)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if scheme == "vless":
        return _vless_outbound(parsed, query)
    if scheme == "trojan":
        return _trojan_outbound(parsed, query)
    if scheme == "ss":
        return _ss_outbound(raw)
    if scheme == "hysteria2":
        return _hysteria2_outbound(parsed, query)

    # xray usually does not support these directly from subscription URI.
    if scheme in {"ssr", "hysteria"}:
        return None

    return None


def _make_xray_config(outbound: dict, socks_port: int) -> dict:
    outbound = dict(outbound)
    outbound["tag"] = "proxy"

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "udp": False,
                },
            }
        ],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": "proxy",
                }
            ],
        },
    }


async def _wait_for_port(
    host: str,
    port: int,
    timeout_seconds: float,
    process: asyncio.subprocess.Process | None = None,
) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds

    while loop.time() < deadline:
        if process is not None and process.returncode is not None:
            return False
        try:
            _, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return True
        except OSError:
            await asyncio.sleep(0.15)

    return False


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return

    try:
        process.terminate()
    except ProcessLookupError:
        return

    try:
        await asyncio.wait_for(process.wait(), timeout=1.5)
        return
    except asyncio.TimeoutError:
        pass

    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=1.5)
            return
        except asyncio.TimeoutError:
            pass

    # Last resort: kill process group (works because we start xray in a new session).
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=1.5)
        except Exception:
            pass


async def _test_single_config(
    original_line: str,
    settings: TesterSettings,
    port: int,
) -> bool:
    outbound = build_xray_outbound(original_line)
    if outbound is None:
        LOGGER.debug("Unsupported config for xray test: %s", original_line[:40])
        return False

    temp_dir = tempfile.mkdtemp(prefix="xray-test-")
    config_path = Path(temp_dir) / "config.json"
    config_path.write_text(
        json.dumps(_make_xray_config(outbound, port), ensure_ascii=False),
        encoding="utf-8",
    )

    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(
            settings.xray_bin,
            "run",
            "-c",
            str(config_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )

        ready = await _wait_for_port(
            "127.0.0.1",
            port,
            settings.startup_wait_seconds,
            process=process,
        )
        if not ready:
            return False

        proxy_url = f"socks5://127.0.0.1:{port}"
        timeout = httpx.Timeout(settings.request_timeout_seconds)
        async with httpx.AsyncClient(proxy=proxy_url, timeout=timeout, follow_redirects=False) as client:
            response = await client.get(settings.pass_url)
        return response.status_code == 204
    except Exception:
        return False
    finally:
        if process is not None:
            await _terminate_process(process)
        shutil.rmtree(temp_dir, ignore_errors=True)


async def _run_single_with_deadline(
    *,
    original_line: str,
    settings: TesterSettings,
    port: int,
) -> bool:
    timeout_seconds = max(1.0, settings.request_timeout_seconds)
    try:
        return await asyncio.wait_for(
            _test_single_config(
                original_line=original_line,
                settings=settings,
                port=port,
            ),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError:
        LOGGER.debug("Config test timed out on port %d after %.2fs", port, timeout_seconds)
        return False


async def _test_batch(
    lines: list[tuple[int, str]],
    settings: TesterSettings,
) -> list[str]:
    tasks = [
        asyncio.create_task(
            _run_single_with_deadline(
                original_line=line,
                settings=settings,
                port=settings.port_start + index,
            )
        )
        for index, line in lines
    ]
    batch_timeout = (
        settings.batch_timeout_seconds
        if settings.batch_timeout_seconds > 0
        else max(1.0, settings.request_timeout_seconds + 1.0)
    )

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=batch_timeout,
        )
    except asyncio.TimeoutError:
        LOGGER.warning("Batch timed out after %.2fs; cancelling pending tests", batch_timeout)
        for task in tasks:
            if not task.done():
                task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)

    working: list[str] = []
    for (_, line), result in zip(lines, results):
        if result is True:
            working.append(line)
    return working


async def test_configs(config_lines: list[str], settings: TesterSettings) -> list[str]:
    if not config_lines:
        _atomic_write_lines(settings.working_output_path, [])
        return []

    if not shutil.which(settings.xray_bin):
        LOGGER.error("Xray binary not found: %s", settings.xray_bin)
        _atomic_write_lines(settings.working_output_path, [])
        return []

    total_input = len(config_lines)
    effective_lines = config_lines
    if settings.max_configs_per_cycle > 0:
        effective_lines = config_lines[: settings.max_configs_per_cycle]
        if len(effective_lines) < total_input:
            LOGGER.info(
                "Limiting tests this cycle: selected=%d total=%d",
                len(effective_lines),
                total_input,
            )

    indexed = list(enumerate(effective_lines))
    working_lines: list[str] = []

    batch_size = max(1, settings.batch_size)
    total_batches = (len(indexed) + batch_size - 1) // batch_size
    for batch_number, start in enumerate(range(0, len(indexed), batch_size), start=1):
        batch = indexed[start : start + batch_size]
        processed_before = len(working_lines)
        LOGGER.info(
            "Testing batch %d/%d (processed=%d/%d, batch_size=%d)",
            batch_number,
            total_batches,
            start,
            len(indexed),
            len(batch),
        )
        batch_working = await _test_batch(batch, settings)
        working_lines.extend(batch_working)
        LOGGER.info(
            "Batch %d/%d result: ok=%d/%d (running_ok=%d)",
            batch_number,
            total_batches,
            len(batch_working),
            len(batch),
            processed_before + len(batch_working),
        )

    _atomic_write_lines(settings.working_output_path, working_lines)
    LOGGER.info(
        "Testing finished: tested=%d total_input=%d working=%d",
        len(indexed),
        total_input,
        len(working_lines),
    )
    return working_lines
