#!/usr/bin/env python3
"""
collect-repository-context.py
Enterprise Security Logging Advisor - Repository Scanner

Scans a repository to identify languages, frameworks, IaC config, databases,
authentication mechanisms, CI/CD configurations, and potential secrets patterns.
Outputs findings as a structured JSON object.
"""

import os
import sys
import json
import re
import errno
import stat
import io

# Directory and file ignore patterns
IGNORE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "dist", "build", "target", 
    ".gemini", "__pycache__", ".pytest_cache", ".mypy_cache", ".idea"
}

# Regex patterns for secret detection (high-confidence only)
SECRETS_PATTERNS = {
    "AWS Access Key ID": re.compile(r"([^A-Z0-9]|^)(AKIA[A-Z0-9]{16})([^A-Z0-9]|$)"),
    "Generic Secret / Password Assignment": re.compile(
        r"(?i)(password|passwd|secret|api[-_]?key|private[-_]?key|auth[-_]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\/\+\=\!@#\$%\^&\*\(\)]{8,}['\"]"
    ),
    "Private Key Header": re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    "Database Connection String": re.compile(r"(mongodb(?:\+srv)?|postgres|mysql|redis):\/\/[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9_\-\.]+"),
}

MAX_FILES_TO_SCAN = 10000
MAX_DIRS_TO_SCAN = 2000
MAX_DIRECTORIES_TO_SCAN = MAX_DIRS_TO_SCAN
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024 # 1 MB

CONTENT_EXTENSIONS = {".json", ".yaml", ".yml", ".tf", ".tfvars", ".conf", ".properties", ".ini", ".env", ".py", ".ts", ".js", ".go", ".java", ".md", ".bicep", ".ps1", ".psm1", ".sh", ".pl", ".pm", ".cs", ".csproj", ".sln", ".rs", ".c", ".cpp", ".rb", ".php", ".swift", ".kt", ".scala"}
SECRET_EXTENSIONS = CONTENT_EXTENSIONS - {".tfvars"}
CONTENT_MANIFESTS = {"package.json", "requirements.txt", "Pipfile", "pyproject.toml", "pom.xml", "build.gradle"}

def open_windows_regular_file(path):
    """Inspect a Windows handle before adopting it as a Python descriptor."""
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
    # GENERIC_READ, share read/write/delete, OPEN_EXISTING, OPEN_REPARSE_POINT.
    handle = kernel.CreateFileW(str(path), 0x80000000, 7, None, 3, 0x00200080, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.GetFileType(handle) != 1:
            raise OSError(errno.EINVAL, "non_regular")
        info = AttributeTagInfo()
        if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.attributes & 0x400:
            raise OSError(errno.ELOOP, "changed")
        if info.attributes & 0x10:
            raise OSError(errno.EINVAL, "non_regular")
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return descriptor  # The descriptor now owns the handle.

def read_bounded_regular_file(path, discovered):
    """Read one unchanged regular file, with a hard cap across all read paths."""
    if discovered.st_size > MAX_FILE_SIZE_BYTES:
        return None, "too_large"

    try:
        if os.name == "nt":
            fd = open_windows_regular_file(path)
        else:
            # Fail closed when the platform cannot prevent symlink following.
            if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
                return None, "unreadable"
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as exc:
        return None, {errno.ELOOP: "changed", errno.EINVAL: "non_regular"}.get(exc.errno, "unreadable")

    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            return None, "non_regular"
        if (
            (opened.st_dev, opened.st_ino) != (discovered.st_dev, discovered.st_ino)
            or opened.st_mtime_ns != discovered.st_mtime_ns
            or (os.name != "nt" and opened.st_ctime_ns != discovered.st_ctime_ns)
        ):
            return None, "changed"
        if opened.st_size > MAX_FILE_SIZE_BYTES:
            return None, "too_large"

        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_FILE_SIZE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_SIZE_BYTES:
                return None, "too_large"

        finished = os.fstat(fd)
        if finished.st_size > MAX_FILE_SIZE_BYTES:
            return None, "too_large"
        if (
            (finished.st_dev, finished.st_ino) != (opened.st_dev, opened.st_ino)
            or finished.st_mtime_ns != opened.st_mtime_ns
            or (os.name != "nt" and finished.st_ctime_ns != opened.st_ctime_ns)
        ):
            return None, "changed"
        return b"".join(chunks).decode("utf-8", errors="ignore"), None
    except OSError:
        return None, "unreadable"
    finally:
        os.close(fd)

def is_ignored(path, root_dir):
    """Checks if a given path should be ignored."""
    try:
        rel = os.path.relpath(path, root_dir)
    except ValueError:
        return False
    if rel == ".":
        return os.path.basename(os.path.abspath(path)) in IGNORE_DIRS
    parts = rel.split(os.sep)
    for part in parts:
        if part in IGNORE_DIRS:
            return True
    return False

def scan_repository(root_dir, max_dirs=None, max_files=None):
    """Performs static analysis on the repository files."""
    effective_max_dirs = max_dirs if max_dirs is not None else int(os.environ.get("COPS_SCANNER_MAX_DIRS", globals().get("MAX_DIRS_TO_SCAN", 2000)))
    effective_max_files = max_files if max_files is not None else int(os.environ.get("COPS_SCANNER_MAX_FILES", globals().get("MAX_FILES_TO_SCAN", 10000)))

    results = {
        "repository_path": os.path.abspath(root_dir),
        "languages": {},
        "frameworks_and_libraries": [],
        "databases": [],
        "identity_and_auth": [],
        "iac_and_cloud": [],
        "cicd": [],
        "secrets_findings": [],
        "scanned_files_count": 0,
        "scanned_directories_count": 0,
        "coverage": "complete",
        "incomplete_coverage": False,
        "partial_scan_notice": None,
        "skipped_files": []
    }

    files_seen = 0
    dirs_seen = 0

    # Configuration file detections
    for root, dirs, files in os.walk(root_dir):
        if is_ignored(root, root_dir):
            dirs[:] = []
            continue

        # Prune ignored directory trees so os.walk does not descend into them
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not is_ignored(os.path.join(root, d), root_dir)]

        if dirs_seen >= effective_max_dirs:
            dirs[:] = []
            results["coverage"] = "partial"
            results["incomplete_coverage"] = True
            results["partial_scan_notice"] = f"Directory budget of {effective_max_dirs} reached; scan is partial."
            break

        dirs_seen += 1
        results["scanned_directories_count"] = dirs_seen

        if files_seen >= effective_max_files:
            dirs[:] = []
            results["coverage"] = "partial"
            results["incomplete_coverage"] = True
            results["partial_scan_notice"] = f"File budget of {effective_max_files} reached; scan is partial."
            break

        for file in files:
            if files_seen >= effective_max_files:
                dirs[:] = []
                results["coverage"] = "partial"
                results["incomplete_coverage"] = True
                results["partial_scan_notice"] = f"File budget of {effective_max_files} reached; scan is partial."
                break
            files_seen += 1
                
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, root_dir)
            
            try:
                discovered = os.lstat(file_path)
            except OSError:
                results["skipped_files"].append({"file": rel_path, "reason": "unreadable"})
                continue

            if stat.S_ISLNK(discovered.st_mode) or getattr(discovered, "st_file_attributes", 0) & 0x400:
                results["skipped_files"].append({"file": rel_path, "reason": "symlink"})
                continue
            if not stat.S_ISREG(discovered.st_mode):
                results["skipped_files"].append({"file": rel_path, "reason": "non_regular"})
                continue

            results["scanned_files_count"] += 1
            ext = os.path.splitext(file)[1].lower()
            content = None
            if discovered.st_size > MAX_FILE_SIZE_BYTES:
                results["skipped_files"].append({"file": rel_path, "reason": "too_large"})
            elif ext in CONTENT_EXTENSIONS or file in CONTENT_MANIFESTS:
                content, reason = read_bounded_regular_file(file_path, discovered)
                if reason:
                    results["skipped_files"].append({"file": rel_path, "reason": reason})

            # Language and core tech detection
            if ext in {".ts", ".tsx", ".js", ".jsx"}:
                results["languages"]["TypeScript/JavaScript"] = results["languages"].get("TypeScript/JavaScript", 0) + 1
            elif ext == ".py":
                results["languages"]["Python"] = results["languages"].get("Python", 0) + 1
            elif ext == ".go":
                results["languages"]["Go"] = results["languages"].get("Go", 0) + 1
            elif ext == ".java":
                results["languages"]["Java"] = results["languages"].get("Java", 0) + 1
            elif ext in {".tf", ".tfvars"}:
                results["languages"]["HashiCorp Configuration Language (HCL)"] = results["languages"].get("HashiCorp Configuration Language (HCL)", 0) + 1
                if "Terraform" not in results["iac_and_cloud"]:
                    results["iac_and_cloud"].append("Terraform")
                if content is not None:
                    for line in io.StringIO(content, newline=None):
                        if "aws_" in line or "provider \"aws\"" in line or "provider 'aws'" in line:
                            if "AWS" not in results["iac_and_cloud"]:
                                results["iac_and_cloud"].append("AWS")
                        if "google_" in line:
                            if "GCP" not in results["iac_and_cloud"]:
                                results["iac_and_cloud"].append("GCP")
                        if "azurerm_" in line or "azure_" in line:
                            if "Azure" not in results["iac_and_cloud"]:
                                results["iac_and_cloud"].append("Azure")
                        if "oci_" in line:
                            if "Oracle Cloud" not in results["iac_and_cloud"]:
                                results["iac_and_cloud"].append("Oracle Cloud")
            elif ext == ".bicep":
                results["languages"]["Bicep"] = results["languages"].get("Bicep", 0) + 1
                if "Azure Bicep" not in results["iac_and_cloud"]:
                    results["iac_and_cloud"].append("Azure Bicep")
            elif ext in {".ps1", ".psm1"}:
                results["languages"]["PowerShell"] = results["languages"].get("PowerShell", 0) + 1
            elif ext == ".sh":
                results["languages"]["Shell Script (Bash)"] = results["languages"].get("Shell Script (Bash)", 0) + 1
            elif ext in {".pl", ".pm"}:
                results["languages"]["Perl"] = results["languages"].get("Perl", 0) + 1
            elif ext in {".cs", ".csproj", ".sln"}:
                results["languages"]["C# (.NET)"] = results["languages"].get("C# (.NET)", 0) + 1
            elif ext == ".rs":
                results["languages"]["Rust"] = results["languages"].get("Rust", 0) + 1
            elif ext in {".c", ".cpp", ".h", ".hpp"}:
                results["languages"]["C/C++"] = results["languages"].get("C/C++", 0) + 1
            elif ext == ".rb":
                results["languages"]["Ruby"] = results["languages"].get("Ruby", 0) + 1
            elif ext == ".php":
                results["languages"]["PHP"] = results["languages"].get("PHP", 0) + 1
            elif ext == ".swift":
                results["languages"]["Swift"] = results["languages"].get("Swift", 0) + 1
            elif ext == ".kt":
                results["languages"]["Kotlin"] = results["languages"].get("Kotlin", 0) + 1
            elif ext == ".scala":
                results["languages"]["Scala"] = results["languages"].get("Scala", 0) + 1
            elif ext == ".json":
                if content is not None and "schema.management.azure.com" in content[:1024]:
                    if "Azure ARM Template" not in results["iac_and_cloud"]:
                        results["iac_and_cloud"].append("Azure ARM Template")

            # Project manifests & dependencies detection
            if content is not None:
                if file == "package.json":
                    try:
                        data = json.loads(content)
                        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                        for dep in deps:
                            if dep in {"express", "koa", "nest", "fastify"}:
                                results["frameworks_and_libraries"].append(f"Node.js Framework: {dep}")
                            if dep in {"pg", "mysql2", "mongoose", "redis", "ioredis", "sequelize", "typeorm"}:
                                results["databases"].append(f"Node.js DB Client: {dep}")
                            if dep in {"jsonwebtoken", "passport", "auth0", "keycloak-connect", "firebase-admin"}:
                                results["identity_and_auth"].append(f"Node.js Auth: {dep}")
                            if dep in {"winston", "pino", "bunyan", "morgan"}:
                                results["frameworks_and_libraries"].append(f"Logging Library: {dep}")
                            if "aws-sdk" in dep or "@aws-sdk" in dep:
                                if "AWS" not in results["iac_and_cloud"]:
                                    results["iac_and_cloud"].append("AWS")
                            if "google-cloud" in dep or "@google-cloud" in dep:
                                if "GCP" not in results["iac_and_cloud"]:
                                    results["iac_and_cloud"].append("GCP")
                            if "azure" in dep or "@azure" in dep:
                                if "Azure" not in results["iac_and_cloud"]:
                                    results["iac_and_cloud"].append("Azure")
                            if "oci" in dep:
                                if "Oracle Cloud" not in results["iac_and_cloud"]:
                                    results["iac_and_cloud"].append("Oracle Cloud")
                    except Exception:
                        pass

                elif file == "requirements.txt" or file == "Pipfile" or file == "pyproject.toml":
                    for line in io.StringIO(content, newline=None):
                        l = line.lower()
                        if "django" in l:
                            results["frameworks_and_libraries"].append("Python Framework: Django")
                        if "flask" in l:
                            results["frameworks_and_libraries"].append("Python Framework: Flask")
                        if "fastapi" in l:
                            results["frameworks_and_libraries"].append("Python Framework: FastAPI")
                        if "sqlalchemy" in l or "psycopg2" in l or "pymongo" in l or "redis" in l:
                            results["databases"].append("Python DB Client")
                        if "jwt" in l or "oauth" in l or "auth0" in l:
                            results["identity_and_auth"].append("Python Auth Library")
                        if "structlog" in l:
                            results["frameworks_and_libraries"].append("Logging Library: structlog")
                        if "boto3" in l or "aws" in l:
                            if "AWS" not in results["iac_and_cloud"]:
                                results["iac_and_cloud"].append("AWS")
                        if "google-cloud" in l:
                            if "GCP" not in results["iac_and_cloud"]:
                                results["iac_and_cloud"].append("GCP")
                        if "azure" in l:
                            if "Azure" not in results["iac_and_cloud"]:
                                results["iac_and_cloud"].append("Azure")
                        if "oci" in l:
                            if "Oracle Cloud" not in results["iac_and_cloud"]:
                                results["iac_and_cloud"].append("Oracle Cloud")

                elif file == "pom.xml" or file == "build.gradle":
                    for line in io.StringIO(content, newline=None):
                        if "spring-boot" in line:
                            if "Java Framework: Spring Boot" not in results["frameworks_and_libraries"]:
                                results["frameworks_and_libraries"].append("Java Framework: Spring Boot")

            # IaC, Containers and Configs
            if file == "Dockerfile":
                results["iac_and_cloud"].append("Docker containerization")
            elif file == "docker-compose.yml" or file == "docker-compose.yaml":
                results["iac_and_cloud"].append("Docker Compose orchestration")
            elif file == "Chart.yaml":
                results["iac_and_cloud"].append("Kubernetes Helm Chart")
            elif "kubernetes" in root.lower() or file == "deployment.yaml" or file == "deployment.yml":
                if "Kubernetes YAML" not in results["iac_and_cloud"]:
                    results["iac_and_cloud"].append("Kubernetes YAML definitions")

            # CI/CD pipelines
            if ".github/workflows" in root:
                if "GitHub Actions" not in results["cicd"]:
                    results["cicd"].append("GitHub Actions")
            elif ".gitlab-ci.yml" in file:
                results["cicd"].append("GitLab CI")
            elif "Jenkinsfile" in file:
                results["cicd"].append("Jenkins Pipeline")

            # File scanning for credentials (text files only)
            if ext in SECRET_EXTENSIONS and content is not None:
                for line_num, line in enumerate(io.StringIO(content, newline=None), 1):
                    for name, pattern in SECRETS_PATTERNS.items():
                        if pattern.search(line):
                            # Masked alert log entry
                            results["secrets_findings"].append({
                                "file": rel_path,
                                "line": line_num,
                                "issue_type": f"Potential {name} detected",
                                "remediation": "Do not commit plain text secrets. Move key/credentials to vault/secrets manager or set as environment variables."
                            })

        if files_seen >= MAX_FILES_TO_SCAN:
            break

    # Deduplicate arrays
    results["frameworks_and_libraries"] = list(set(results["frameworks_and_libraries"]))
    results["databases"] = list(set(results["databases"]))
    results["identity_and_auth"] = list(set(results["identity_and_auth"]))
    results["iac_and_cloud"] = list(set(results["iac_and_cloud"]))
    results["cicd"] = list(set(results["cicd"]))

    return results

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Enterprise Security Logging Advisor - Repository Scanner")
    parser.add_argument("target_dir", nargs="?", default=".", help="Directory to scan")
    parser.add_argument("--max-dirs", type=int, default=None, help="Maximum directories to visit")
    parser.add_argument("--max-files", type=int, default=None, help="Maximum files to scan")
    args = parser.parse_args()

    if not os.path.isdir(args.target_dir):
        print(json.dumps({"error": f"Path '{args.target_dir}' is not a valid directory."}, indent=2))
        sys.exit(1)

    scan_data = scan_repository(args.target_dir, max_dirs=args.max_dirs, max_files=args.max_files)
    print(json.dumps(scan_data, indent=2))

if __name__ == "__main__":
    main()
