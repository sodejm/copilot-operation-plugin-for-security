---
name: network-messaging-services
description: Assess email services (SMTP, POP3, IMAP), chat (IRC), and message brokers/queues (AMQP/RabbitMQ, NATS, IBM MQ, Kafka, MQTT) with bounded message budgets, synthetic canary verification, cleanup receipts, and messaging privilege candidate routing.
---

# Mail, Messaging, and Message Broker Services

1. **Protocol-Specific Mail, Chat, and Broker Probes**:
   - Assess exposure of mail services (SMTP, POP3, IMAP), real-time chat (IRC), and message brokers/queues (RabbitMQ/AMQP, NATS, IBM MQ, Kafka, MQTT) across approved targets.
   - Ground assessments in observed protocol responses, versions, and configurations.

2. **Bounded Message Budgets & Zero Mass Outbound Relaying**:
   - Enforce bounded message budgets (default 5 messages) to verify delivery, queue interaction, and boundary enforcement.
   - Prohibit and block bulk mail delivery, external domain spamming, and unconstrained queue flooding.

3. **Authentication Prerequisites & Messaging Privilege Routing**:
   - Determine whether services require authentication (`none`, `anonymous`, `default_credentials`, `user_password`, `client_cert`, `token_or_api_key`, `sasl`, `unknown`).
   - Extract `MessagingPrivilegeCandidate` entries for unauthorized relay, broker takeover, or message interception workflows.

4. **Canary Validation and Verifiable Cleanup Receipts**:
   - Validate access controls using benign canary identifiers (`canary_mail_probe`, `canary_queue_probe`) without disrupting production message flows.
   - Emit verified `CleanupReceipt` records confirming rollback and artifact removal (`verified_removed`).

5. **Inaccessible != Secure Truth Boundary**:
   - Strictly mark unreachable, filtered, or connection-refused services as `inaccessible` (with `auth_prerequisite: unknown`). Never claim unverified services are protected or secure.

6. **CLI Invocation**:
   ```bash
   python3 -m cops messaging-services assess --targets mail01.corp.internal --canary-id "canary_mail_probe" --output msg_report.json
   python3 -m cops messaging-services candidates msg_report.json --output msg_candidates.json
   python3 -m cops messaging-services cleanup msg_report.json --output cleanup_receipts.json
   python3 -m cops messaging-services inspect msg_report.json
   ```
