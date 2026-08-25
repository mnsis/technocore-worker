from __future__ import annotations

import http.client
import json
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from worker.protocol import COMMIT_RE, REPOSITORY_RE

GITHUB_HOST = "api.github.com"
GITHUB_PORT = 443
MAX_RESPONSE_BYTES = 262_144
MAX_REQUESTS_PER_JOB = 3
REDIRECT_STATUSES = {301, 302, 307, 308}


class GitHubBoundaryError(RuntimeError):
    pass


class ResponseTooLarge(GitHubBoundaryError):
    pass


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Getter(Protocol):
    def __call__(self, path: str) -> HTTPResponse: ...


@dataclass(frozen=True)
class Verification:
    checks: dict[str, Any]
    resolved_sha: str | None
    repository_full_name: str | None


def redirect_path(location: str) -> str:
    parsed = urllib.parse.urlsplit(location)
    if (
        parsed.scheme != "https"
        or parsed.hostname != GITHUB_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, GITHUB_PORT)
        or parsed.fragment
    ):
        raise GitHubBoundaryError("redirect left the GitHub API boundary")
    if not (
        parsed.path.startswith("/repos/") or parsed.path.startswith("/repositories/")
    ):
        raise GitHubBoundaryError("redirect target is not an allowed GitHub API endpoint")
    return urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))


class HTTPSGetter:
    def __init__(self, *, connect_timeout: float = 5.0, read_timeout: float = 10.0):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    def __call__(self, path: str) -> HTTPResponse:
        current = path
        for attempt in range(2):
            connection = http.client.HTTPSConnection(
                GITHUB_HOST, GITHUB_PORT, timeout=self.connect_timeout
            )
            try:
                connection.request(
                    "GET",
                    current,
                    headers={
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                        "User-Agent": "technocore-worker/0.2",
                    },
                )
                response = connection.getresponse()
                if connection.sock is not None:
                    connection.sock.settimeout(self.read_timeout)
                headers = {key.lower(): value for key, value in response.getheaders()}
                declared = headers.get("content-length")
                if declared is not None and int(declared) > MAX_RESPONSE_BYTES:
                    raise ResponseTooLarge("GitHub response exceeds byte limit")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ResponseTooLarge("GitHub response exceeds byte limit")
                result = HTTPResponse(response.status, headers, body)
            finally:
                connection.close()
            if result.status not in REDIRECT_STATUSES:
                return result
            if attempt or "location" not in result.headers:
                raise GitHubBoundaryError("GitHub redirect could not be followed safely")
            current = redirect_path(result.headers["location"])
        raise GitHubBoundaryError("too many GitHub redirects")


class GitHubVerifier:
    def __init__(self, getter: Getter | None = None):
        self.get = getter or HTTPSGetter()

    @staticmethod
    def _json(response: HTTPResponse) -> dict[str, Any]:
        try:
            value = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise GitHubBoundaryError("GitHub returned malformed JSON") from error
        if not isinstance(value, dict):
            raise GitHubBoundaryError("GitHub response was not an object")
        return value

    @staticmethod
    def _failure(response: HTTPResponse) -> tuple[str, str]:
        if response.status == 404:
            return "NOT_FOUND", "not_found_or_inaccessible"
        if response.status in {403, 429}:
            return "UNAVAILABLE", "rate_limited"
        return "UNAVAILABLE", "github_http_error"

    def verify(
        self, repository: str, commit_sha: str, file_path: str | None = None
    ) -> Verification:
        match = REPOSITORY_RE.fullmatch(repository)
        if match is None or COMMIT_RE.fullmatch(commit_sha) is None:
            raise ValueError("verification inputs were not normalized")
        owner, name = match.group("owner"), match.group("name")
        try:
            repo_response = self.get(f"/repos/{owner}/{name}")
            if repo_response.status != 200:
                status, reason = self._failure(repo_response)
                return Verification(
                    checks={
                        "commit": {"status": "NOT_CHECKED"},
                        "requested_file": {"status": "NOT_CHECKED"},
                        "repository": {"reason": reason, "status": status},
                    },
                    resolved_sha=None,
                    repository_full_name=None,
                )
            repo = self._json(repo_response)
            full_name = repo.get("full_name")
            private = repo.get("private")
            if not isinstance(full_name, str) or REPOSITORY_RE.fullmatch(full_name) is None:
                raise GitHubBoundaryError("GitHub repository response lacked canonical identity")
            if private is not False:
                return Verification(
                    checks={
                        "commit": {"status": "NOT_CHECKED"},
                        "requested_file": {"status": "NOT_CHECKED"},
                        "repository": {"reason": "not_public", "status": "NOT_FOUND"},
                    },
                    resolved_sha=None,
                    repository_full_name=None,
                )
            canonical_owner, canonical_name = full_name.split("/", 1)
            commit_response = self.get(
                f"/repos/{canonical_owner}/{canonical_name}/commits/{commit_sha}?per_page=1&page=1"
            )
            repository_check: dict[str, Any] = {
                "full_name": full_name,
                "status": "CONFIRMED",
            }
            if full_name.casefold() != repository.casefold():
                repository_check["renamed"] = True
            if commit_response.status != 200:
                status, reason = self._failure(commit_response)
                return Verification(
                    checks={
                        "commit": {"reason": reason, "status": status},
                        "requested_file": {"status": "NOT_CHECKED"},
                        "repository": repository_check,
                    },
                    resolved_sha=None,
                    repository_full_name=full_name,
                )
            commit = self._json(commit_response)
            resolved = commit.get("sha")
            if not isinstance(resolved, str) or not COMMIT_RE.fullmatch(resolved):
                raise GitHubBoundaryError("GitHub commit response lacked an exact SHA")
            if resolved.casefold() != commit_sha.casefold():
                raise GitHubBoundaryError("GitHub resolved a different commit SHA")
            file_check: dict[str, Any] = {"status": "NOT_CHECKED"}
            if file_path is not None:
                commit_details = commit.get("commit")
                tree = commit_details.get("tree") if isinstance(commit_details, dict) else None
                tree_sha = tree.get("sha") if isinstance(tree, dict) else None
                if not isinstance(tree_sha, str) or not COMMIT_RE.fullmatch(tree_sha):
                    raise GitHubBoundaryError("GitHub commit response lacked a tree SHA")
                tree_response = self.get(
                    f"/repos/{canonical_owner}/{canonical_name}/git/trees/{tree_sha}?recursive=1"
                )
                if tree_response.status != 200:
                    status, reason = self._failure(tree_response)
                    file_check = {"reason": reason, "status": status}
                else:
                    tree_payload = self._json(tree_response)
                    entries = tree_payload.get("tree")
                    if not isinstance(entries, list):
                        raise GitHubBoundaryError("GitHub tree response lacked entries")
                    present = any(
                        isinstance(entry, dict)
                        and entry.get("path") == file_path
                        and entry.get("type") == "blob"
                        for entry in entries
                    )
                    if present:
                        file_check = {"path": file_path, "status": "CONFIRMED"}
                    elif tree_payload.get("truncated") is True:
                        file_check = {"reason": "tree_truncated", "status": "UNAVAILABLE"}
                    else:
                        file_check = {"path": file_path, "status": "NOT_FOUND"}
            return Verification(
                checks={
                    "commit": {"sha": resolved.lower(), "status": "CONFIRMED"},
                    "requested_file": file_check,
                    "repository": repository_check,
                },
                resolved_sha=resolved.lower(),
                repository_full_name=full_name,
            )
        except (GitHubBoundaryError, OSError, ValueError) as error:
            reason = "response_too_large" if isinstance(error, ResponseTooLarge) else "github_unavailable"
            return Verification(
                checks={
                    "commit": {"status": "NOT_CHECKED"},
                    "requested_file": {"status": "NOT_CHECKED"},
                    "repository": {"reason": reason, "status": "UNAVAILABLE"},
                },
                resolved_sha=None,
                repository_full_name=None,
            )
