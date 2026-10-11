---
name: network-messaging-services
description: Assess email services (SMTP, POP3, IMAP), chat (IRC), and message brokers/queues (AMQP/RabbitMQ, NATS, IBM MQ, Kafka, MQTT) with bounded message budgets, synthetic canary verification, cleanup receipts, and messaging privilege candidate routing.
---

# Mail, Messaging, and Message Broker Services

The socket collector checks TCP reachability only. The synthetic collector evaluates supplied fixture data. Neither collector sends protocol messages or verifies live relay, authentication, delivery, or cleanup.

1. **Protocol-Specific Mail, Chat, and Broker Probes**:
   - Assess exposure of mail services (SMTP, POP3, IMAP), real-time chat (IRC), and message brokers/queues (RabbitMQ/AMQP, NATS, IBM MQ, Kafka, MQTT) across approved targets.
   - Ground configuration assessments in explicitly supplied synthetic evidence.

2. **Bounded Message Budgets & Zero Mass Outbound Relaying**:
   - Require an allowlisted destination and, for mail, an allowlisted recipient before synthetic canary validation. Retention must be active and at most 86400 seconds.
   - Accept at most 5 observed fixture messages (default budget 5). A canary requires a positive budget. The collectors do not send messages.

3. **Authentication Prerequisites & Messaging Privilege Routing**:
   - Determine whether services require authentication (`none`, `anonymous`, `default_credentials`, `user_password`, `client_cert`, `token_or_api_key`, `sasl`, `unknown`).
   - Extract `MessagingPrivilegeCandidate` entries for unauthorized relay, broker takeover, or message interception workflows.

4. **Canary Validation and Verifiable Cleanup Receipts**:
   - Validate a synthetic canary only when fixture evidence matches its identifier, route, recipient, delivery time, and message budget.
   - Export `CleanupReceipt` records only when matching fixture evidence confirms cleanup within retention. The hash binds the retention start and duration to delivery and cleanup timestamps, which report import rechecks. It detects report changes but does not authenticate the fixture or confirm live rollback.

5. **Inaccessible != Secure Truth Boundary**:
   - Strictly mark unreachable, filtered, or connection-refused services as `inaccessible` (with `auth_prerequisite: unknown`). Never claim unverified services are protected or secure.

6. **CLI Invocation**:
   ```bash
   python3 -m cops messaging-services assess --targets mail01.corp.internal --services smtp --mode synthetic --offline-targets approved-fixtures.json --canary-id "canary_mail_probe" --canary-destination "mailbox:canary" --allow-canary-destination "mailbox:canary" --canary-recipient "canary@example.test" --allow-canary-recipient "canary@example.test" --canary-retention-seconds 3600 --message-budget 5 --output msg_report.json
   python3 -m cops messaging-services candidates msg_report.json --output msg_candidates.json
   python3 -m cops messaging-services cleanup msg_report.json --output cleanup_receipts.json
   python3 -m cops messaging-services inspect msg_report.json
   ```
