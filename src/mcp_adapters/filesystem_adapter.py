"""
Filesystem Adapter for PentestAgent.

Provides a wrapper for filesystem operations with error handling.
This adapter can be extended to use Filesystem MCP when available.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional, Union


class FilesystemError(Exception):
    """Base exception for filesystem operations."""
    pass


class FileNotFoundError(FilesystemError):
    """Raised when a file is not found."""
    pass


class DirectoryNotFoundError(FilesystemError):
    """Raised when a directory is not found."""
    pass


class PermissionError(FilesystemError):
    """Raised when permission is denied."""
    pass


class FilesystemAdapter:
    """
    Adapter for filesystem operations.

    Provides a consistent interface for file and directory operations
    with comprehensive error handling. Can be extended to integrate
    with Filesystem MCP.
    """

    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        """
        Initialize FilesystemAdapter.

        Args:
            base_path: Optional base path to restrict operations to.
                       If provided, all paths are resolved relative to this.
        """
        self.base_path = Path(base_path).resolve() if base_path else None

    def _resolve_path(self, path: Union[str, Path]) -> Path:
        """
        Resolve a path, optionally relative to base_path.

        Args:
            path: Path to resolve.

        Returns:
            Resolved absolute path.

        Raises:
            FilesystemError: If path escapes base_path (security check).
        """
        resolved = Path(path).resolve()

        if self.base_path:
            # Security check: ensure path is within base_path
            try:
                resolved.relative_to(self.base_path)
            except ValueError:
                raise FilesystemError(
                    f"Path '{path}' is outside allowed base path '{self.base_path}'"
                )

        return resolved

    # ==================== File Operations ====================

    def read_file(self, path: Union[str, Path], encoding: str = "utf-8") -> str:
        """
        Read a text file.

        Args:
            path: Path to file.
            encoding: Text encoding.

        Returns:
            File contents as string.

        Raises:
            FileNotFoundError: If file does not exist.
            PermissionError: If read permission denied.
        """
        resolved = self._resolve_path(path)

        try:
            return resolved.read_text(encoding=encoding)
        except builtins.FileNotFoundError:
            raise FileNotFoundError(f"File not found: {path}")
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {path}")

    def read_bytes(self, path: Union[str, Path]) -> bytes:
        """
        Read a binary file.

        Args:
            path: Path to file.

        Returns:
            File contents as bytes.
        """
        resolved = self._resolve_path(path)

        try:
            return resolved.read_bytes()
        except builtins.FileNotFoundError:
            raise FileNotFoundError(f"File not found: {path}")
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {path}")

    def write_file(
        self,
        path: Union[str, Path],
        content: str,
        encoding: str = "utf-8",
        create_dirs: bool = True
    ) -> None:
        """
        Write a text file.

        Args:
            path: Path to file.
            content: Content to write.
            encoding: Text encoding.
            create_dirs: If True, create parent directories if needed.
        """
        resolved = self._resolve_path(path)

        try:
            if create_dirs:
                resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(content, encoding=encoding)
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {path}")

    def write_bytes(
        self,
        path: Union[str, Path],
        content: bytes,
        create_dirs: bool = True
    ) -> None:
        """
        Write a binary file.

        Args:
            path: Path to file.
            content: Content to write.
            create_dirs: If True, create parent directories if needed.
        """
        resolved = self._resolve_path(path)

        try:
            if create_dirs:
                resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_bytes(content)
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {path}")

    def append_file(
        self,
        path: Union[str, Path],
        content: str,
        encoding: str = "utf-8",
        create_dirs: bool = True
    ) -> None:
        """
        Append to a text file.

        Args:
            path: Path to file.
            content: Content to append.
            encoding: Text encoding.
            create_dirs: If True, create parent directories if needed.
        """
        resolved = self._resolve_path(path)

        try:
            if create_dirs:
                resolved.parent.mkdir(parents=True, exist_ok=True)

            with resolved.open("a", encoding=encoding) as f:
                f.write(content)
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {path}")

    def delete_file(self, path: Union[str, Path]) -> bool:
        """
        Delete a file.

        Args:
            path: Path to file.

        Returns:
            True if file was deleted, False if not found.
        """
        resolved = self._resolve_path(path)

        if not resolved.exists():
            return False

        try:
            resolved.unlink()
            return True
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {path}")

    def file_exists(self, path: Union[str, Path]) -> bool:
        """Check if a file exists."""
        resolved = self._resolve_path(path)
        return resolved.is_file()

    def get_file_size(self, path: Union[str, Path]) -> int:
        """
        Get file size in bytes.

        Args:
            path: Path to file.

        Returns:
            File size in bytes.
        """
        resolved = self._resolve_path(path)

        if not resolved.exists():
            raise FileNotFoundError(f"File not found: {path}")

        return resolved.stat().st_size

    # ==================== Directory Operations ====================

    def create_directory(
        self,
        path: Union[str, Path],
        parents: bool = True,
        exist_ok: bool = True
    ) -> None:
        """
        Create a directory.

        Args:
            path: Path to directory.
            parents: If True, create parent directories as needed.
            exist_ok: If True, don't raise error if directory exists.
        """
        resolved = self._resolve_path(path)

        try:
            resolved.mkdir(parents=parents, exist_ok=exist_ok)
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {path}")

    def delete_directory(
        self,
        path: Union[str, Path],
        recursive: bool = False
    ) -> bool:
        """
        Delete a directory.

        Args:
            path: Path to directory.
            recursive: If True, delete contents recursively.

        Returns:
            True if deleted, False if not found.
        """
        resolved = self._resolve_path(path)

        if not resolved.exists():
            return False

        try:
            if recursive:
                shutil.rmtree(resolved)
            else:
                resolved.rmdir()
            return True
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {path}")
        except OSError as e:
            raise FilesystemError(f"Cannot delete directory: {e}")

    def directory_exists(self, path: Union[str, Path]) -> bool:
        """Check if a directory exists."""
        resolved = self._resolve_path(path)
        return resolved.is_dir()

    def list_directory(
        self,
        path: Union[str, Path],
        pattern: str = "*",
        recursive: bool = False
    ) -> list[Path]:
        """
        List directory contents.

        Args:
            path: Path to directory.
            pattern: Glob pattern to filter results.
            recursive: If True, search recursively.

        Returns:
            List of paths matching the pattern.
        """
        resolved = self._resolve_path(path)

        if not resolved.exists():
            raise DirectoryNotFoundError(f"Directory not found: {path}")

        if recursive:
            return list(resolved.rglob(pattern))
        else:
            return list(resolved.glob(pattern))

    # ==================== Copy/Move Operations ====================

    def copy_file(
        self,
        src: Union[str, Path],
        dst: Union[str, Path],
        create_dirs: bool = True
    ) -> None:
        """
        Copy a file.

        Args:
            src: Source path.
            dst: Destination path.
            create_dirs: If True, create destination directories if needed.
        """
        src_resolved = self._resolve_path(src)
        dst_resolved = self._resolve_path(dst)

        if not src_resolved.exists():
            raise FileNotFoundError(f"Source file not found: {src}")

        try:
            if create_dirs:
                dst_resolved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_resolved, dst_resolved)
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {src} -> {dst}")

    def move_file(
        self,
        src: Union[str, Path],
        dst: Union[str, Path],
        create_dirs: bool = True
    ) -> None:
        """
        Move a file.

        Args:
            src: Source path.
            dst: Destination path.
            create_dirs: If True, create destination directories if needed.
        """
        src_resolved = self._resolve_path(src)
        dst_resolved = self._resolve_path(dst)

        if not src_resolved.exists():
            raise FileNotFoundError(f"Source file not found: {src}")

        try:
            if create_dirs:
                dst_resolved.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(src_resolved, dst_resolved)
        except builtins.PermissionError:
            raise PermissionError(f"Permission denied: {src} -> {dst}")


# Import builtins to avoid shadowing built-in exceptions
import builtins
