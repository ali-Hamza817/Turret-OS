"""
turret_harvest.parsers.git_parser
===================================
Git repository commit metadata extractor using pygit2.
Extracts: commit author, committer, timestamp, message, changed files,
and diff stats per commit.

Security:
- pygit2 operates on local repo paths only; path validated by caller.
- No remote operations are performed.
- TODO(security): Validate repo path is within allowed source root
  before opening (enforced by HarvestOrchestrator but add defense-in-depth).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from turret_harvest.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class GitParser(BaseParser):
    """Extract metadata from git repositories (one record per commit)."""

    SUPPORTED_FORMATS = frozenset({"git-commit"})

    def extract(self, path: Path) -> dict[str, Any]:
        """
        Extract metadata for the HEAD commit of the repo at *path*.
        For bulk extraction of all commits, use extract_all_commits().
        """
        try:
            return self._extract_head(path)
        except Exception as exc:
            logger.warning("Git parse failure on %s: %s", path, exc)
            return {"tika_xdm": {}, "exif": None, "custom": {"parse_error": str(exc)}}

    def _extract_head(self, repo_path: Path) -> dict[str, Any]:
        import pygit2  # type: ignore[import]

        repo = pygit2.Repository(str(repo_path))
        head = repo.head
        commit = repo.get(head.target)

        author = commit.author
        committer = commit.committer

        tika_xdm = {
            "dc:creator": f"{author.name} <{author.email}>",
            "dc:title": commit.message.split("\n")[0][:200],
            "cp:created": commit.author.time,
            "cp:modified": commit.committer.time,
            "git:commit_id": str(commit.id),
            "git:branch": head.shorthand,
        }

        custom: dict[str, Any] = {
            "commit_id": str(commit.id),
            "author_name": author.name,
            "author_email": author.email,
            "author_ts": author.time,
            "committer_name": committer.name,
            "committer_email": committer.email,
            "committer_ts": committer.time,
            "message": commit.message,
            "parent_ids": [str(p) for p in commit.parent_ids],
        }

        # Diff stats
        try:
            if commit.parents:
                diff = repo.diff(commit.parents[0], commit)
                custom["files_changed"] = diff.stats.files_changed
                custom["insertions"] = diff.stats.insertions
                custom["deletions"] = diff.stats.deletions
                custom["changed_files"] = [p.delta.new_file.path for p in diff]
        except Exception as e:
            logger.debug("Diff stats failed: %s", e)

        return {"tika_xdm": tika_xdm, "exif": None, "custom": custom}

    def extract_all_commits(self, repo_path: Path, max_commits: int = 10000) -> list[dict[str, Any]]:
        """
        Walk all commits in the repo and return a list of metadata dicts.
        Used by the harvest orchestrator for git repositories.
        """
        try:
            import pygit2  # type: ignore[import]
            repo = pygit2.Repository(str(repo_path))
            results = []
            for commit in repo.walk(repo.head.target, pygit2.GIT_SORT_TIME):
                if len(results) >= max_commits:
                    break
                results.append(self._extract_commit(repo, commit))
            return results
        except Exception as exc:
            logger.warning("Git walk failed on %s: %s", repo_path, exc)
            return []

    def _extract_commit(self, repo: Any, commit: Any) -> dict[str, Any]:
        author = commit.author
        return {
            "tika_xdm": {
                "dc:creator": f"{author.name} <{author.email}>",
                "git:commit_id": str(commit.id),
            },
            "exif": None,
            "custom": {
                "commit_id": str(commit.id),
                "author_name": author.name,
                "author_email": author.email,
                "author_ts": author.time,
                "message": commit.message[:500],
            },
        }
