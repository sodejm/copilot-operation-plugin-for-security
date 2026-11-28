"""Handle-relative, fail-closed local file I/O for Windows."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path


class WindowsIOError(OSError):
    """A Windows secure-I/O primitive failed."""


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")

    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _FILE_SHARE_ALL = 0x7
    _FILE_OPEN = 1
    _FILE_CREATE = 2
    _FILE_DIRECTORY_FILE = 0x1
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x20
    _FILE_NON_DIRECTORY_FILE = 0x40
    _FILE_OPEN_REPARSE_POINT = 0x200000
    _FILE_OPEN_FOR_BACKUP_INTENT = 0x4000
    _FILE_READ_DATA = 0x1
    _FILE_WRITE_DATA = 0x2
    _FILE_APPEND_DATA = 0x4
    _FILE_READ_ATTRIBUTES = 0x80
    _FILE_WRITE_ATTRIBUTES = 0x100
    _DELETE = 0x10000
    _SYNCHRONIZE = 0x100000
    _OBJ_CASE_INSENSITIVE = 0x40
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_RENAME_INFORMATION_CLASS = 10

    class _UnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class _ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_UnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_ssize_t), ("Information", ctypes.c_size_t)]

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("CreationTime", wintypes.FILETIME),
            ("LastAccessTime", wintypes.FILETIME),
            ("LastWriteTime", wintypes.FILETIME),
            ("VolumeSerialNumber", wintypes.DWORD),
            ("FileSizeHigh", wintypes.DWORD),
            ("FileSizeLow", wintypes.DWORD),
            ("NumberOfLinks", wintypes.DWORD),
            ("FileIndexHigh", wintypes.DWORD),
            ("FileIndexLow", wintypes.DWORD),
        ]

    class _FileRenameInformation(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", wintypes.BOOLEAN),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * 1),
        ]

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = _kernel32.ReadFile.argtypes
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.FlushFileBuffers.restype = wintypes.BOOL
    _ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    _ntdll.NtCreateFile.restype = ctypes.c_long
    _ntdll.NtSetInformationFile.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_IoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    _ntdll.NtSetInformationFile.restype = ctypes.c_long


def _require_windows() -> None:
    if os.name != "nt":
        raise WindowsIOError("Windows secure I/O is unavailable")


def _raise_last_error(message: str) -> None:
    raise WindowsIOError(ctypes.get_last_error(), message)


def _close(handle: int | None) -> None:
    if handle is not None and handle != _INVALID_HANDLE_VALUE:
        _kernel32.CloseHandle(handle)


def _validate_component(component: str) -> None:
    if (
        not component
        or component in (".", "..")
        or any(character in component for character in ("/", "\\", ":"))
        or any(ord(character) < 32 for character in component)
    ):
        raise WindowsIOError("invalid Windows path component")


def _root_and_parts(path: Path) -> tuple[str, tuple[str, ...]]:
    absolute = Path(os.path.abspath(path))
    if not absolute.anchor:
        raise WindowsIOError("path has no Windows anchor")
    parts = absolute.parts
    if not parts or parts[0] != absolute.anchor:
        raise WindowsIOError("invalid Windows path")
    relative = tuple(parts[1:])
    for part in relative:
        _validate_component(part)
    return absolute.anchor, relative


def _open_root(anchor: str) -> int:
    handle = _kernel32.CreateFileW(
        anchor,
        _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        _FILE_SHARE_ALL,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        _raise_last_error("cannot open path anchor")
    return handle


def _open_relative(parent: int, name: str, access: int, disposition: int, options: int) -> int:
    buffer = ctypes.create_unicode_buffer(name)
    value = _UnicodeString(
        len(name.encode("utf-16-le")),
        ctypes.sizeof(buffer),
        ctypes.cast(buffer, wintypes.LPWSTR),
    )
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes), parent, ctypes.pointer(value), _OBJ_CASE_INSENSITIVE, None, None
    )
    result = wintypes.HANDLE()
    status_block = _IoStatusBlock()
    status = _ntdll.NtCreateFile(
        ctypes.byref(result),
        access,
        ctypes.byref(attributes),
        ctypes.byref(status_block),
        None,
        0,
        _FILE_SHARE_ALL,
        disposition,
        options | _FILE_OPEN_REPARSE_POINT | _FILE_SYNCHRONOUS_IO_NONALERT,
        None,
        0,
    )
    if status < 0:
        raise WindowsIOError(int(status), "handle-relative file operation failed")
    return result.value


def _information(handle: int) -> _ByHandleFileInformation:
    information = _ByHandleFileInformation()
    if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        _raise_last_error("cannot inspect opened file")
    if information.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise WindowsIOError("reparse points are forbidden")
    return information


def _identity(information: _ByHandleFileInformation) -> tuple[int, ...]:
    return (
        information.VolumeSerialNumber,
        information.FileIndexHigh,
        information.FileIndexLow,
        information.NumberOfLinks,
        information.FileSizeHigh,
        information.FileSizeLow,
        information.LastWriteTime.dwHighDateTime,
        information.LastWriteTime.dwLowDateTime,
    )


def _object_identity(information: _ByHandleFileInformation) -> tuple[int, int, int]:
    return (
        information.VolumeSerialNumber,
        information.FileIndexHigh,
        information.FileIndexLow,
    )


def _walk(path: Path, *, create_final_directory: bool = False) -> list[int]:
    anchor, parts = _root_and_parts(path)
    if create_final_directory and not parts:
        raise WindowsIOError("output path must name a new directory")
    handles = [_open_root(anchor)]
    try:
        _information(handles[0])
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            disposition = _FILE_CREATE if final and create_final_directory else _FILE_OPEN
            access = _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
            if final and create_final_directory:
                access |= _FILE_WRITE_DATA | _FILE_APPEND_DATA
            handles.append(
                _open_relative(
                    handles[-1],
                    part,
                    access,
                    disposition,
                    _FILE_DIRECTORY_FILE | _FILE_OPEN_FOR_BACKUP_INTENT,
                )
            )
            _information(handles[-1])
        return handles
    except Exception:
        for handle in reversed(handles):
            _close(handle)
        raise


def read_regular(root: Path, relative_parts: list[str], limit: int, remaining: int) -> tuple[bytes, tuple[int, ...]]:
    """Read a single-link regular file through held directory handles."""
    _require_windows()
    if not relative_parts:
        raise WindowsIOError("input path has no file component")
    for part in relative_parts:
        _validate_component(part)
    handles = _walk(root)
    file_handle = None
    try:
        parent = handles[-1]
        for part in relative_parts[:-1]:
            handle = _open_relative(
                parent,
                part,
                _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
                _FILE_OPEN,
                _FILE_DIRECTORY_FILE | _FILE_OPEN_FOR_BACKUP_INTENT,
            )
            handles.append(handle)
            _information(handle)
            parent = handle
        file_handle = _open_relative(
            parent,
            relative_parts[-1],
            _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            _FILE_OPEN,
            _FILE_NON_DIRECTORY_FILE,
        )
        before = _information(file_handle)
        if before.NumberOfLinks != 1:
            raise WindowsIOError("multiply linked files are forbidden")
        size = (before.FileSizeHigh << 32) | before.FileSizeLow
        if size > limit:
            raise OverflowError("file_limit")
        if size > remaining:
            raise OverflowError("total_byte_limit")
        chunks: list[bytes] = []
        read = 0
        allowed = min(limit, remaining)
        while True:
            block = ctypes.create_string_buffer(min(65536, allowed + 1 - read))
            count = wintypes.DWORD()
            if not _kernel32.ReadFile(file_handle, block, len(block), ctypes.byref(count), None):
                _raise_last_error("cannot read opened file")
            if count.value == 0:
                break
            read += count.value
            if read > allowed:
                raise OverflowError("file_limit" if limit <= remaining else "total_byte_limit")
            chunks.append(block.raw[: count.value])
        after = _information(file_handle)
        if _identity(before) != _identity(after) or read != ((after.FileSizeHigh << 32) | after.FileSizeLow):
            raise WindowsIOError("file changed during read")
        return b"".join(chunks), _identity(after)
    finally:
        _close(file_handle)
        for handle in reversed(handles):
            _close(handle)


def _write_all(handle: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = wintypes.DWORD()
        block = (ctypes.c_char * len(view)).from_buffer_copy(view)
        if not _kernel32.WriteFile(handle, block, len(view), ctypes.byref(count), None):
            _raise_last_error("cannot write report file")
        if count.value <= 0:
            raise WindowsIOError("short report write")
        view = view[count.value :]
    if not _kernel32.FlushFileBuffers(handle):
        _raise_last_error("cannot flush report file")


def _rename_into_directory(handle: int, directory: int, name: str) -> None:
    encoded = name.encode("utf-16-le")
    size = _FileRenameInformation.FileName.offset + len(encoded)
    storage = ctypes.create_string_buffer(size)
    information = ctypes.cast(storage, ctypes.POINTER(_FileRenameInformation)).contents
    information.ReplaceIfExists = False
    information.RootDirectory = directory
    information.FileNameLength = len(encoded)
    ctypes.memmove(
        ctypes.addressof(storage) + _FileRenameInformation.FileName.offset,
        encoded,
        len(encoded),
    )
    status_block = _IoStatusBlock()
    status = _ntdll.NtSetInformationFile(
        handle,
        ctypes.byref(status_block),
        storage,
        size,
        _FILE_RENAME_INFORMATION_CLASS,
    )
    if status < 0:
        raise WindowsIOError(int(status), "cannot publish completion marker")


def _verify_output_identity(output: Path, expected: tuple[int, int, int]) -> None:
    verification_handles = _walk(output)
    try:
        if _object_identity(_information(verification_handles[-1])) != expected:
            raise WindowsIOError("output path changed during report publication")
    finally:
        for handle in reversed(verification_handles):
            _close(handle)


def _publish_completion(
    output: Path,
    directory: int,
    directory_identity: tuple[int, int, int],
    staging: int,
) -> None:
    _verify_output_identity(output, directory_identity)
    _rename_into_directory(staging, directory, "completion.json")


def write_files(output: Path, contents: dict[str, bytes], staging_name: str) -> None:
    """Create a report directory and atomically publish its completion marker."""
    _require_windows()
    for name in (*contents, staging_name):
        _validate_component(name)
    handles = _walk(output, create_final_directory=True)
    directory = handles[-1]
    staging = None
    try:
        directory_identity = _object_identity(_information(directory))
        completion = contents.get("completion.json")
        for name, data in contents.items():
            if name == "completion.json":
                continue
            handle = _open_relative(
                directory,
                name,
                _FILE_WRITE_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
                _FILE_CREATE,
                _FILE_NON_DIRECTORY_FILE,
            )
            try:
                _information(handle)
                _write_all(handle, data)
            finally:
                _close(handle)
        if completion is not None:
            staging = _open_relative(
                directory,
                staging_name,
                _FILE_WRITE_DATA | _FILE_READ_ATTRIBUTES | _FILE_WRITE_ATTRIBUTES | _DELETE | _SYNCHRONIZE,
                _FILE_CREATE,
                _FILE_NON_DIRECTORY_FILE,
            )
            _information(staging)
            _write_all(staging, completion)
            _publish_completion(output, directory, directory_identity, staging)
        _verify_output_identity(output, directory_identity)
    finally:
        _close(staging)
        for handle in reversed(handles):
            _close(handle)
