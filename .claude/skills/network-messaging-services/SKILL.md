---
name: network-messaging-services
description: Assess email services (SMTP, POP3, IMAP), chat (IRC), and message brokers/queues (AMQP/RabbitMQ, NATS, IBM MQ, Kafka, MQTT) with bounded message budgets, synthetic canary verification, cleanup receipts, and messaging privilege candidate routing.
---

# Mail, Messaging, and Message Broker Services Assessment

Execute authorized, bounded exposure and configuration assessments across mail transfer and retrieval agents, real-time chat, and message queuing/streaming brokers under strict Rules of Engagement and operational boundaries.

## Core Capabilities

1. **Protocol-Specific Coverage**:
   - **Mail Transfer & Retrieval**:
     - **SMTP (25, 587, 465)**: Evaluates open mail relaying to external destinations, VRFY/EXPN/RCPT TO recipient enumeration, STARTTLS enforcement, and SPF/DKIM/DMARC routing boundaries.
     - **POP3 (110, 995)**: Detects plaintext USER/PASS authentication over unencrypted port 110, missing STLS / POP3S encryption, and unauthenticated mailbox access.
     - **IMAP (143, 993)**: Probes anonymous login, missing STARTTLS / IMAPS encryption, SASL/PLAIN exposure over cleartext, and unauthenticated folder listing.
   - **Real-Time Chat**:
     - **IRC (6667, 6697)**: Detects unauthenticated operator status (`OPER`), cleartext channel administration, and hardcoded oper credentials.
   - **Message Brokers & Streaming**:
     - **RabbitMQ / AMQP (5672, 15672)**: Probes default `guest`/`guest` credentials on loopback or external interfaces, open HTTP Management API access on port 15672, and unauthenticated vhost routing.
     - **NATS (4222, 8222)**: Detects unauthenticated client connections, cluster routing exposure, and missing token/NKey authorization.
     - **IBM MQ (1414)**: Assesses blank or misconfigured `MCAUSER` on `SVRCONN` channels granting unauthenticated `mqadmin` execution.
     - **Apache Kafka (9092)**: Evaluates unauthenticated `PLAINTEXT` broker listeners, missing SASL/SCRAM or mTLS authentication, and unrestricted topic consumption/publishing.
     - **MQTT (1883)**: Detects anonymous client connections (`allow_anonymous true`), wildcards (`#`) subscription, and unencrypted publish/subscribe streams.

2. **Bounded Message Budgets & Zero Mass Outbound Relaying**:
   - Technical probes strictly enforce a bounded message budget (default 5 messages/probes) to verify delivery, queue interaction, and boundary enforcement.
   - **Zero Mass Outbound Relaying**: Bulk mail delivery, external domain spamming, and unconstrained queue flooding are strictly prohibited and architecturally blocked.

3. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If a mail or message broker service is timed out, connection-refused, filtered, or unreachable from the probe vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes.
   - A service is **NEVER** reported as `protected` or `hardened` merely because it failed to respond. Only positive verification of authentication enforcement or relay rejection warrants a `protected` status.

4. **Canary Validation and Verifiable Cleanup Receipts**:
   - Uses non-destructive canary identifiers (e.g. `canary_mail_probe`, `canary_queue_probe`) to verify message ingestion and delivery boundaries.
   - Every assessment verifying canary artifacts generates a cryptographically hashed `CleanupReceipt` confirming that temporary test messages or queues were purged (`verified_removed`).

5. **Messaging Privilege Candidate Routing**:
   - Discovered misconfigurations and open relays are structured as `MessagingPrivilegeCandidate` records:
     - `smtp_open_relay`: Open mail relay accepting arbitrary external recipients.
     - `smtp_user_enumeration`: SMTP VRFY or RCPT TO command revealing valid usernames.
     - `pop3_plaintext_auth`: Unencrypted POP3 credential transmission.
     - `imap_anonymous_login`: Unauthenticated mailbox traversal.
     - `irc_unauthenticated_operator`: Unauthenticated IRC operator access.
     - `rabbitmq_guest_default_creds`: Default RabbitMQ `guest` credentials.
     - `rabbitmq_open_management`: Unauthenticated RabbitMQ HTTP Management API.
     - `nats_unauthenticated_cluster`: Unauthenticated NATS client pub/sub.
     - `ibmmq_blank_channel`: IBM MQ SVRCONN channel with blank MCAUSER.
     - `kafka_unauthenticated_broker`: Unauthenticated Kafka cluster access.
     - `mqtt_anonymous_read_write`: Unauthenticated MQTT broker pub/sub.
   - Binds cryptographic evidence hashes, auth prerequisites, and privilege impact ratings (`unauthorized_relay`, `broker_takeover`, `credential_harvesting`, `data_exfiltration`, `message_tampering`, `remote_code_execution`) for handoff to host and lateral movement specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

## CLI Usage

### 1. Assess Mail, Chat, and Message Broker Services
```bash
python3 -m cops messaging-services assess \
  --targets "198.51.100.40,mail01.corp.internal" \
  --vantage internal \
  --canary-id "canary_mail_probe" \
  --message-budget 5 \
  --output messaging_assessment.json
```

Or via the discovery namespace:
```bash
python3 -m cops discovery messaging assess \
  --targets "198.51.100.40,mail01.corp.internal" \
  --vantage internal \
  --output messaging_assessment.json
```

### 2. Export Messaging Privilege Candidates for Lateral Movement Workflows
```bash
python3 -m cops messaging-services candidates messaging_assessment.json \
  --output messaging_candidates.json
```

### 3. Export Verified Cleanup Receipts
```bash
python3 -m cops messaging-services cleanup messaging_assessment.json \
  --output cleanup_receipts.json
```

### 4. Inspect Summary, Privilege Candidates, and Truth-in-Advertising Metrics
```bash
python3 -m cops messaging-services inspect messaging_assessment.json
```
