from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class GitPushSettings:
    enabled: bool = True
    repo_dir: Path = Path(".")
    remote: str = "origin"
    branch: str = "main"
    timeout_seconds: float = 30.0
    author_name: str = "collector-bot"
    author_email: str = "collector-bot@localhost"
    generated_files: tuple[Path, Path] = (
        Path("collection-of-collector.txt"),
        Path("collection-of-collectors-working.txt"),
    )


@dataclass(slots=True)
class PushResult:
    attempted: bool
    committed: bool
    pushed: bool
    commit_sha: str | None
    message: str


@dataclass(slots=True)
class _GitCommandResult:
    returncode: int
    stdout: str
    stderr: str


def _build_commit_message() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"chore(data): update generated collector outputs ({timestamp})"


def _ensure_repo_paths(settings: GitPushSettings) -> list[str]:
    repo_root = settings.repo_dir.resolve()
    path_args: list[str] = []

    for file_path in settings.generated_files:
        absolute_path = file_path if file_path.is_absolute() else repo_root / file_path
        try:
            relative_path = absolute_path.resolve().relative_to(repo_root)
        except ValueError:
            continue
        path_args.append(str(relative_path))

    return path_args


async def _run_git(settings: GitPushSettings, *args: str) -> _GitCommandResult:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"

    process = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=str(settings.repo_dir),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_raw, stderr_raw = await asyncio.wait_for(
            process.communicate(), timeout=max(1.0, settings.timeout_seconds)
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return _GitCommandResult(
            returncode=-1,
            stdout="",
            stderr=(
                "git command timed out after "
                f"{max(1.0, settings.timeout_seconds):.1f}s: git {' '.join(args)}"
            ),
        )

    stdout = stdout_raw.decode("utf-8", errors="replace").strip()
    stderr = stderr_raw.decode("utf-8", errors="replace").strip()
    return _GitCommandResult(returncode=process.returncode or 0, stdout=stdout, stderr=stderr)


def _compact_error(command: _GitCommandResult) -> str:
    if command.stderr:
        return command.stderr.splitlines()[0][:240]
    if command.stdout:
        return command.stdout.splitlines()[0][:240]
    return "unknown git error"


async def push_generated_files(settings: GitPushSettings, reason: str) -> PushResult:
    if not settings.enabled:
        return PushResult(
            attempted=False,
            committed=False,
            pushed=False,
            commit_sha=None,
            message="git auto-push disabled",
        )

    repo_root = settings.repo_dir.resolve()
    if not (repo_root / ".git").exists():
        return PushResult(
            attempted=False,
            committed=False,
            pushed=False,
            commit_sha=None,
            message=f"missing git repo at {repo_root}",
        )

    path_args = _ensure_repo_paths(settings)
    if not path_args:
        return PushResult(
            attempted=False,
            committed=False,
            pushed=False,
            commit_sha=None,
            message="no generated files are inside repo root",
        )

    remote_check = await _run_git(settings, "remote", "get-url", settings.remote)
    if remote_check.returncode != 0:
        return PushResult(
            attempted=False,
            committed=False,
            pushed=False,
            commit_sha=None,
            message=(
                f"git remote '{settings.remote}' not configured: "
                f"{_compact_error(remote_check)}"
            ),
        )

    status_result = await _run_git(settings, "status", "--porcelain", "--", *path_args)
    if status_result.returncode != 0:
        return PushResult(
            attempted=True,
            committed=False,
            pushed=False,
            commit_sha=None,
            message=f"failed to inspect git status: {_compact_error(status_result)}",
        )

    if not status_result.stdout:
        return PushResult(
            attempted=True,
            committed=False,
            pushed=False,
            commit_sha=None,
            message="no generated file changes to push",
        )

    add_result = await _run_git(settings, "add", "--", *path_args)
    if add_result.returncode != 0:
        return PushResult(
            attempted=True,
            committed=False,
            pushed=False,
            commit_sha=None,
            message=f"git add failed: {_compact_error(add_result)}",
        )

    commit_result = await _run_git(
        settings,
        "-c",
        f"user.name={settings.author_name}",
        "-c",
        f"user.email={settings.author_email}",
        "commit",
        "-m",
        _build_commit_message(),
        "--",
        *path_args,
    )
    if commit_result.returncode != 0:
        combined = (commit_result.stdout + "\n" + commit_result.stderr).lower()
        if "nothing to commit" in combined:
            return PushResult(
                attempted=True,
                committed=False,
                pushed=False,
                commit_sha=None,
                message="no generated file changes to push",
            )
        return PushResult(
            attempted=True,
            committed=False,
            pushed=False,
            commit_sha=None,
            message=f"git commit failed: {_compact_error(commit_result)}",
        )

    sha_result = await _run_git(settings, "rev-parse", "HEAD")
    commit_sha = sha_result.stdout.splitlines()[0].strip() if sha_result.returncode == 0 and sha_result.stdout else None

    push_result = await _run_git(settings, "push", settings.remote, f"HEAD:{settings.branch}")
    if push_result.returncode != 0:
        return PushResult(
            attempted=True,
            committed=True,
            pushed=False,
            commit_sha=commit_sha,
            message=f"git push failed: {_compact_error(push_result)}",
        )

    return PushResult(
        attempted=True,
        committed=True,
        pushed=True,
        commit_sha=commit_sha,
        message=f"pushed generated files for cycle '{reason}' to {settings.remote}/{settings.branch}",
    )
