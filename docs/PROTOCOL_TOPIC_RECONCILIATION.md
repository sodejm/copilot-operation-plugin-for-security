# Historical protocol topic reconciliation

The [machine-readable inventory](../catalog/protocol-topics.json) maps every Markdown topic under [`1.Scanning/IT-Ports`](https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/1.Scanning/IT-Ports) at source commit `4c118399602212f205c91e8f01e418e226fa320c`. It contains 70 unique, sorted paths. The SHA-256 of those paths joined with a newline, including the final newline, is `cec7246d3a2117680b3f550d40a0ac659a12b24597262f275ca82c5c7bf86c9e`. The inventory test checks the count, ordering, duplicates, digest, service taxonomy, and presence of each named evidence test.

## What coverage means

| Status | Topics | Evidence boundary |
| --- | ---: | --- |
| `offline_model` | 62 | A named test exercises a deterministic collector fixture for the listed service type. This does not establish a live protocol exchange, target vulnerability, or technique success. |
| `environment_limit` | 8 | There is no matching deterministic protocol fixture in this scope. The row states the missing capability or environmental dependency. |

The inventory keeps `technique_applicability` separate from `source_tool_maintenance`. Applicability is conditional on an authorized target's version and configuration and requires laboratory validation. Tool maintenance has not been assessed for each topic, so every topic records `not_assessed`. A maintained tool does not prove that a technique applies, and an archived tool does not make a historical technique inapplicable.

The eight explicit environment limits are ident, WHOIS, r-services, mDNS, RTSP, Echo, Finger, and generic HTTP. The generic HTTP topic belongs to the separate web inventory workflow. Five mapped topics have narrower coverage than their source titles: MSRPC models port 135 but not 593; RabbitMQ management exposure is a simulated flag without an HTTP API exchange; IPsec models IKEv1 Aggressive Mode but not ESP, AH, or broader negotiation; RabbitMQ's fixture does not cover arbitrary AMQP implementations; and the IPP fixture does not cover CUPS-specific versions or administration. Each limitation is attached to its inventory row.

## Legacy service model effects

The legacy collector covers nine service types: NDMP, iSCSI, IPMI, Cisco Smart Install, TACACS+, IKEv1, PPTP, SOCKS, and Squid. `OfflineSyntheticLegacyCollector` uses supplied fixtures to exercise all nine models. Its canary flags, proxy policy fields, privilege candidates, and cleanup receipts are synthetic model output. They do not record a remote action.

`StandardSocketLegacyCollector`, selected by `--mode live` (the CLI defaults to `--mode synthetic`), attempts a TCP connection or sends a UDP datagram. A successful socket operation is `unconfirmed`; an unreachable one is `inaccessible`, not secure. A UDP send does not establish that a service is present. The socket collector does not parse a protocol response, authenticate, send traffic through a proxy, test egress restrictions, execute code, change state, validate a canary, create or remove an artifact, or produce a privilege candidate. Its cleanup receipt list is empty. Authorization flags affect fixture branches; they do not turn a socket observation into evidence of any of those effects. The [legacy service skill](../.agents/skills/network-legacy-and-proxy-services/SKILL.md) and [planner playbook](../plugins/offensive-security/attack-surface-planner/docs/PLAYBOOK.md) use these same boundaries.

## Retained historical laboratory procedure

The [pinned research provenance](../catalog/provenance.json) retains item `s02-008`, a historical CrackMapExec reference for credential testing across SMB and WinRM. The [upstream CrackMapExec repository](https://github.com/byt3bl33d3r/CrackMapExec) is archived. Its maintenance state is a property of that tool; the underlying authentication technique may still be relevant on a particular system. This reference is outside the 70-topic source and does not count as one of their tested collector mappings. The related COPS SMB audit scenario `COPS-E04.04-S01` does not implement credential stuffing.

For a retained, authorized lab study, use an isolated SMB or WinRM test host and disposable accounts. Record the service version, authentication configuration, account lockout policy, and explicit test budget. Use a currently maintained, approved tool to run only the bounded authentication cases in that lab; capture server-side logs and distinguish accepted credentials, rejected credentials, and lockouts. Reset accounts and verify the lab state afterward. Re-evaluate whether the technique applies to the observed version and configuration. Do not treat the archived command or an offline COPS fixture as a validated live procedure. No live lab run is claimed here.

The pinned TACACS+ topic also links to Loki and `tacacs_crack`, whose referenced GitHub repositories were unavailable when checked for this reconciliation. That observation establishes only that those links could not be resolved; it does not establish the state of forks, packages, or the TACACS+ authentication technique. Retain the topic for authorized lab analysis and reselect a maintained tool before any test.
