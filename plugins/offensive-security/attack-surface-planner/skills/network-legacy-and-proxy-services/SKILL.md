---
name: network-legacy-and-proxy-services
description: "Use for requests to review legacy network and proxy services. Interpret the nine legacy and proxy service fixture models and bounded socket observations without treating reachability or simulated conditions as verified protocol findings."
---

# Legacy Enterprise, Management, and Proxy Services

The NDMP, iSCSI, IPMI, Cisco Smart Install, TACACS+, IKEv1, PPTP, SOCKS, and Squid models cover fixture-defined scenarios. The CLI defaults to `--mode synthetic`; pass `--offline-targets` with mock target data to exercise those scenarios. Fixture findings, canary records, privilege candidates, and cleanup receipts are simulated and do not establish target behavior or remote cleanup.

`--mode live` uses a bounded socket collector. A TCP connection or UDP send is recorded as `unconfirmed`; an unreachable socket is `inaccessible`, never secure. The collector does not parse protocol responses, test authentication or proxy egress, validate canaries, execute code, change state, or produce privilege candidates or cleanup receipts. Authorization flags do not add those probes.

Use `candidates` and `cleanup` only to export records already present in a report. Confirm any operational finding in an authorized environment before specialist handoff. See the [playbook](../../docs/PLAYBOOK.md) for the report truth boundaries.

```bash
python3 -m cops legacy-services assess --targets 198.51.100.60 --mode synthetic --offline-targets mock_targets.json --output legacy_fixture_report.json
python3 -m cops legacy-services assess --targets 198.51.100.60 --mode live --services ndmp,iscsi --output legacy_socket_report.json
python3 -m cops legacy-services inspect legacy_socket_report.json
python3 -m cops legacy-services candidates legacy_fixture_report.json --output legacy_candidates.json
python3 -m cops legacy-services cleanup legacy_fixture_report.json --output cleanup_receipts.json
```
