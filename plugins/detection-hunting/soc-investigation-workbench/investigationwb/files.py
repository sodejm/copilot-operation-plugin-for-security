"""Bounded reads from regular files, checked on the opened descriptor."""

from contextlib import contextmanager
import os
from pathlib import Path
import stat

from .engine import ContractError, require

MAX_BYTES = 8 * 1024 * 1024


def _open_windows(path: Path, nofollow: bool) -> int:
    # Windows has no O_NOFOLLOW. Inspect the opened handle itself before adopting
    # it as a Python descriptor, so a final reparse point cannot redirect a read.
    import ctypes
    from ctypes import wintypes
    import msvcrt

    class AttributeTagInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                   wintypes.LPVOID, wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    flags = 0x80 | (0x00200000 if nofollow else 0)  # NORMAL | OPEN_REPARSE_POINT
    handle = kernel.CreateFileW(str(path), 0x80000000, 7, None, 3, flags, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        require(kernel.GetFileType(handle) == 1, "Input must be a regular file.")
        info = AttributeTagInfo()
        if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        require(not (info.attributes & 0x10), "Input must be a regular file.")
        require(not nofollow or not (info.attributes & 0x400),
                "Dependency input cannot be a reparse point.")
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return descriptor  # The descriptor now owns the handle.


@contextmanager
def open_regular(path: Path, *, nofollow: bool = False):
    try:
        if os.name == "nt":
            descriptor = _open_windows(path, nofollow)
        else:
            flags = os.O_RDONLY | os.O_NONBLOCK
            if nofollow:
                require(hasattr(os, "O_NOFOLLOW"), "Safe dependency reads are unavailable.")
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
        try:
            stream = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                    "Input must be a regular file.")
            yield stream
    except OSError as exc:
        raise ContractError("Input file is unavailable or unsafe.") from exc


def read_regular(path: Path, *, nofollow: bool = False) -> bytes:
    with open_regular(path, nofollow=nofollow) as stream:
        content = stream.read(MAX_BYTES + 1)
    require(len(content) <= MAX_BYTES, "Input exceeds the 8 MiB limit.")
    return content
