"""Service identification, banner analysis, and visible uncertainty calibration."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from .active_models import (
    ConfidenceLevel,
    InferredFingerprint,
    ObservedConfiguration,
)


def infer_service_fingerprint(
    target_host: str,
    port: int,
    protocol: str,
    observed_config: ObservedConfiguration,
) -> InferredFingerprint:
    """Derive service, product, and version fingerprints with visible uncertainty explanations."""
    uncertainty_reasons: list[str] = []
    evidence_sources: list[str] = []
    raw_banner = observed_config.raw_banner or ""
    headers = observed_config.http_headers or {}
    tls = observed_config.tls

    if (
        protocol == "udp"
        and observed_config.protocol_metadata.get("probe_payload") == "dns_root_ns_query"
        and observed_config.protocol_metadata.get("dns_response_validated") is True
    ):
        return InferredFingerprint(
            service_name="dns",
            product=None,
            version=None,
            confidence=ConfidenceLevel.MEDIUM.value,
            uncertainty_reasons=["Matching DNS response does not authenticate the server or establish a product or version"],
            evidence_sources=["matched_dns_query_response"],
        )

    # 1. SSH Analysis
    if protocol == "tcp" and raw_banner.startswith("SSH-"):
        evidence_sources.append("ssh_protocol_banner")
        match = re.match(r"^SSH-([0-9.]+)-([^\s_]+)(?:_([^\s]+))?(?:\s+(.*))?", raw_banner.strip())
        if match:
            _, prod, ver, _ = match.groups()
            uncertainty_reasons.append("SSH banner is self-reported and does not verify product, version, or host OS")

            return InferredFingerprint(
                service_name="ssh",
                product=prod or "OpenSSH",
                version=ver,
                os_inferred=None,
                confidence=ConfidenceLevel.MEDIUM.value,
                uncertainty_reasons=uncertainty_reasons,
                evidence_sources=evidence_sources,
            )

    # 2. HTTP / HTTPS Analysis
    server_header = headers.get("server") or headers.get("Server")
    is_http_response = protocol == "tcp" and (observed_config.http_status is not None or bool(headers))

    if is_http_response:
        service_name = "https" if tls is not None else "http"
        evidence_sources.append("http_service_probe")
        product = None
        version = None
        os_inferred = None
        confidence = ConfidenceLevel.MEDIUM.value

        # Check for CDN / Edge Proxy fronting
        has_cloudflare = any("cloudflare" in (server_header or "").lower() or "cf-ray" in k.lower() for k in headers)
        has_cloudfront = any(
            "cloudfront" in (server_header or "").lower()
            or "x-amz-cf-id" in k.lower()
            or "cloudfront" in str(v).lower()
            for k, v in headers.items()
        )

        if has_cloudflare:
            product = "Cloudflare Edge Proxy"
            confidence = ConfidenceLevel.UNCERTAIN.value
            uncertainty_reasons.append("Cloudflare reverse proxy fronting origin; backend origin service is obscured")
            evidence_sources.append("cloudflare_edge_headers")
        elif has_cloudfront:
            product = "Amazon CloudFront CDN"
            confidence = ConfidenceLevel.UNCERTAIN.value
            uncertainty_reasons.append("AWS CloudFront CDN fronting origin; backend origin service is obscured")
            evidence_sources.append("cloudfront_edge_headers")
        elif server_header:
            evidence_sources.append("http_server_header")
            uncertainty_reasons.append("Server header can be masked, rewritten, or falsified by reverse proxies")

            # Parse common server tokens
            if "nginx" in server_header.lower():
                product = "nginx"
                m = re.search(r"nginx/([0-9.]+)", server_header, re.IGNORECASE)
                if m:
                    version = m.group(1)
            elif "apache" in server_header.lower():
                product = "Apache httpd"
                m = re.search(r"Apache/([0-9.]+)", server_header, re.IGNORECASE)
                if m:
                    version = m.group(1)
            elif "microsoft-iis" in server_header.lower():
                product = "Microsoft IIS"
                m = re.search(r"Microsoft-IIS/([0-9.]+)", server_header, re.IGNORECASE)
                if m:
                    version = m.group(1)
            else:
                product = server_header.split()[0]
                confidence = ConfidenceLevel.LOW.value

        # Check TLS certificate SAN match
        if tls:
            evidence_sources.append("tls_handshake")
            if tls.valid_until:
                try:
                    # Check certificate expiry if ISO or standard format
                    exp_dt = datetime.fromisoformat(tls.valid_until.replace("Z", "+00:00"))
                    if exp_dt < datetime.now(UTC):
                        uncertainty_reasons.append(
                            "TLS certificate is expired; target service configuration may be unmaintained"
                        )
                        confidence = ConfidenceLevel.UNCERTAIN.value
                except (TypeError, ValueError):
                    uncertainty_reasons.append("TLS certificate expiry date could not be parsed")
                    confidence = ConfidenceLevel.UNCERTAIN.value

            # Domain mismatch check (if target is a named hostname, not an IP)
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_host):
                host_lower = target_host.lower()
                all_names = [tls.subject_cn.lower()] if tls.subject_cn else []
                all_names.extend(s.lower() for s in tls.sans)

                matched = False
                for name in all_names:
                    if name == host_lower:
                        matched = True
                        break
                    if name.startswith("*.") and host_lower.endswith(name[1:]):
                        matched = True
                        break

                if all_names and not matched:
                    uncertainty_reasons.append(
                        f"TLS certificate Common Name / SAN ({all_names[:2]}) does not match target host '{target_host}'; potential proxy or SNI consolidation"
                    )
                    confidence = ConfidenceLevel.LOW.value

        if not product and not uncertainty_reasons:
            uncertainty_reasons.append("HTTP response had no descriptive product banner or Server header")
            confidence = ConfidenceLevel.PROVISIONAL.value

        return InferredFingerprint(
            service_name=service_name,
            product=product,
            version=version,
            os_inferred=os_inferred,
            confidence=confidence,
            uncertainty_reasons=uncertainty_reasons,
            evidence_sources=evidence_sources,
        )

    # A TLS handshake establishes encryption, but cannot identify the application protocol.
    if protocol == "tcp" and tls is not None:
        uncertainty_reasons.append("TLS handshake did not identify the application protocol")
        if tls.valid_until:
            try:
                exp_dt = datetime.fromisoformat(tls.valid_until.replace("Z", "+00:00"))
                if exp_dt < datetime.now(UTC):
                    uncertainty_reasons.append(
                        "TLS certificate is expired; target service configuration may be unmaintained"
                    )
            except (TypeError, ValueError):
                uncertainty_reasons.append("TLS certificate expiry date could not be parsed")
        return InferredFingerprint(
            service_name="tls",
            product=None,
            version=None,
            confidence=ConfidenceLevel.UNCERTAIN.value,
            uncertainty_reasons=uncertainty_reasons,
            evidence_sources=["tls_handshake"],
        )

    # 3. SMTP Analysis. A generic 220 greeting is shared by multiple protocols.
    if (
        protocol == "tcp"
        and raw_banner.startswith("220")
        and re.search(r"\b(?:esmtp|smtp|postfix|exim)\b", raw_banner, re.IGNORECASE)
    ):
        evidence_sources.append("smtp_banner")
        product = "SMTP Server"
        version = None
        if "postfix" in raw_banner.lower():
            product = "Postfix"
        elif "exim" in raw_banner.lower():
            product = "Exim"
        uncertainty_reasons.append("SMTP greeting is self-reported and does not verify product or host OS")
        return InferredFingerprint(
            service_name="smtp",
            product=product,
            version=version,
            os_inferred=None,
            confidence=ConfidenceLevel.MEDIUM.value,
            uncertainty_reasons=uncertainty_reasons,
            evidence_sources=evidence_sources,
        )

    # 4. FTP Analysis
    if (
        protocol == "tcp"
        and raw_banner.startswith("220")
        and re.search(r"\b(?:ftp|vsftpd|proftpd|pure-ftpd)\b", raw_banner, re.IGNORECASE)
    ):
        evidence_sources.append("ftp_banner")
        product = "FTP Server"
        m = re.search(r"(vsftpd|proftpd|pure-ftpd)(?:\s+([0-9.]+))?", raw_banner, re.IGNORECASE)
        if m:
            product = m.group(1)
            version = m.group(2)
        else:
            version = None
        uncertainty_reasons.append("FTP greeting is self-reported and does not verify product or host OS")
        return InferredFingerprint(
            service_name="ftp",
            product=product,
            version=version,
            confidence=ConfidenceLevel.MEDIUM.value,
            uncertainty_reasons=uncertainty_reasons,
            evidence_sources=evidence_sources,
        )

    # A port number or generic greeting cannot establish which service answered.
    uncertainty_reasons.append(
        "TCP response did not identify an application protocol"
        if protocol == "tcp" and raw_banner
        else (
            "Port accepted TCP connection but emitted no descriptive protocol banner"
            if protocol == "tcp"
            else "UDP datagram response did not identify an application protocol"
        )
    )
    return InferredFingerprint(
        service_name=f"unknown-{port}",
        product=None,
        version=None,
        confidence=ConfidenceLevel.UNCERTAIN.value,
        uncertainty_reasons=uncertainty_reasons,
        evidence_sources=["tcp_banner" if raw_banner and protocol == "tcp" else "port_association"],
    )
