from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
import uvicorn
from dotenv import load_dotenv

from collector import CollectorSettings, collect_and_dedup
from github_sync import GitPushSettings, push_generated_files
from tester import TesterSettings, test_configs

LOGGER = logging.getLogger(__name__)
load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "true" if default else "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class AppSettings:
    collectors_source_file: Path = Path(os.getenv("COLLECTORS_SOURCE_FILE", "collectors.txt"))
    merged_output_file: Path = Path(os.getenv("MERGED_OUTPUT_FILE", "collection-of-collector.txt"))
    working_output_file: Path = Path(
        os.getenv("WORKING_OUTPUT_FILE", "collection-of-collectors-working.txt")
    )

    collection_interval_seconds: int = int(os.getenv("COLLECTION_INTERVAL_SECONDS", "1800"))
    fetch_timeout_seconds: float = float(os.getenv("FETCH_TIMEOUT_SECONDS", "20"))

    test_batch_size: int = int(os.getenv("TEST_BATCH_SIZE", "25"))
    test_timeout_seconds: float = float(os.getenv("TEST_TIMEOUT_SECONDS", "15"))
    test_batch_timeout_seconds: float = float(os.getenv("TEST_BATCH_TIMEOUT_SECONDS", "0"))
    xray_startup_wait_seconds: float = float(os.getenv("XRAY_STARTUP_WAIT_SECONDS", "8"))
    xray_port_start: int = int(os.getenv("XRAY_PORT_START", "20000"))
    xray_bin: str = os.getenv("XRAY_BIN", "xray")
    pass_test_url: str = os.getenv("PASS_TEST_URL", "https://www.google.com/generate_204")
    run_startup_cycle: bool = _env_bool("RUN_STARTUP_CYCLE", True)
    test_max_configs_per_cycle: int = int(os.getenv("TEST_MAX_CONFIGS_PER_CYCLE", "0"))
    git_auto_push_enabled: bool = _env_bool("GIT_AUTO_PUSH_ENABLED", True)
    git_push_remote: str = os.getenv("GIT_PUSH_REMOTE", "origin")
    git_push_branch: str = os.getenv("GIT_PUSH_BRANCH", "main")
    git_push_timeout_seconds: float = float(os.getenv("GIT_PUSH_TIMEOUT_SECONDS", "30"))
    git_commit_author_name: str = os.getenv("GIT_COMMIT_AUTHOR_NAME", "collector-bot")
    git_commit_author_email: str = os.getenv(
        "GIT_COMMIT_AUTHOR_EMAIL", "collector-bot@localhost"
    )

    uvicorn_host: str = os.getenv("UVICORN_HOST", "0.0.0.0")
    uvicorn_port: int = int(os.getenv("UVICORN_PORT", "8000"))


def build_settings() -> AppSettings:
    return AppSettings()


settings = build_settings()
collector_settings = CollectorSettings(
    source_list_path=settings.collectors_source_file,
    fetch_timeout_seconds=settings.fetch_timeout_seconds,
    merged_output_path=settings.merged_output_file,
)
tester_settings = TesterSettings(
    xray_bin=settings.xray_bin,
    batch_size=settings.test_batch_size,
    request_timeout_seconds=settings.test_timeout_seconds,
    batch_timeout_seconds=settings.test_batch_timeout_seconds,
    startup_wait_seconds=settings.xray_startup_wait_seconds,
    port_start=settings.xray_port_start,
    working_output_path=settings.working_output_file,
    pass_url=settings.pass_test_url,
    max_configs_per_cycle=settings.test_max_configs_per_cycle,
)
git_push_settings = GitPushSettings(
    enabled=settings.git_auto_push_enabled,
    repo_dir=Path.cwd(),
    remote=settings.git_push_remote,
    branch=settings.git_push_branch,
    timeout_seconds=settings.git_push_timeout_seconds,
    author_name=settings.git_commit_author_name,
    author_email=settings.git_commit_author_email,
    generated_files=(settings.merged_output_file, settings.working_output_file),
)


_cycle_lock = asyncio.Lock()
_scheduler_task: asyncio.Task | None = None
_startup_task: asyncio.Task | None = None
_stop_event = asyncio.Event()


async def _read_text_file(path: Path) -> str | None:
    if not path.exists():
        return None
    return await asyncio.to_thread(path.read_text, encoding="utf-8", errors="replace")


async def run_cycle(reason: str) -> None:
    if _cycle_lock.locked():
        LOGGER.info("Skipping %s cycle because a run is in progress", reason)
        return

    async with _cycle_lock:
        LOGGER.info("Cycle started (%s)", reason)
        try:
            merged_lines = await collect_and_dedup(collector_settings)
            await test_configs(merged_lines, tester_settings)
            push_result = await push_generated_files(git_push_settings, reason)
            if push_result.pushed:
                LOGGER.info(
                    "Git push success: remote=%s branch=%s sha=%s",
                    git_push_settings.remote,
                    git_push_settings.branch,
                    push_result.commit_sha or "unknown",
                )
            elif "no generated file changes" in push_result.message or "disabled" in push_result.message:
                LOGGER.info("Git push skipped: %s", push_result.message)
            elif push_result.attempted:
                LOGGER.warning("Git push skipped/failed after attempt: %s", push_result.message)
            else:
                LOGGER.warning("Git push skipped: %s", push_result.message)
        except asyncio.CancelledError:
            LOGGER.info("Cycle cancelled (%s)", reason)
            raise
        except Exception:
            LOGGER.exception("Cycle failed (%s)", reason)
        else:
            LOGGER.info("Cycle finished (%s)", reason)


async def _scheduler_loop() -> None:
    interval = max(1, settings.collection_interval_seconds)
    try:
        while not _stop_event.is_set():
            try:
                await asyncio.wait_for(_stop_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                await run_cycle("scheduled")
    except asyncio.CancelledError:
        LOGGER.info("Scheduler loop cancelled")
        raise


async def _cancel_task(task: asyncio.Task | None, name: str) -> None:
    if task is None:
        return
    if task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        LOGGER.info("%s cancelled", name)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global _scheduler_task, _startup_task
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    _stop_event.clear()

    # Optionally run first cycle immediately, then continue at interval.
    if settings.run_startup_cycle:
        _startup_task = asyncio.create_task(run_cycle("startup"))
    _scheduler_task = asyncio.create_task(_scheduler_loop())
    try:
        yield
    finally:
        _stop_event.set()
        await _cancel_task(_startup_task, "Startup cycle task")
        await _cancel_task(_scheduler_task, "Scheduler task")
        _startup_task = None
        _scheduler_task = None


app = FastAPI(title="Collector of Collectors V2Ray", lifespan=lifespan)


@app.get("/collection-of-collector.txt", response_class=PlainTextResponse)
async def serve_merged_file() -> PlainTextResponse:
    content = await _read_text_file(settings.merged_output_file)
    if content is None:
        return PlainTextResponse("collection-of-collector.txt not found\n", status_code=404)
    return PlainTextResponse(content)


@app.get("/collection-of-collectors-working.txt", response_class=PlainTextResponse)
async def serve_working_file() -> PlainTextResponse:
    content = await _read_text_file(settings.working_output_file)
    if content is None:
        return PlainTextResponse(
            "collection-of-collectors-working.txt not found\n",
            status_code=404,
        )
    return PlainTextResponse(content)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.uvicorn_host,
        port=settings.uvicorn_port,
        reload=False,
        timeout_graceful_shutdown=5,
    )
