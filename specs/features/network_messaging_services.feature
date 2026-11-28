Feature: Mail, Messaging, and Message Broker Services Assessment
  As an authorized penetration tester or attack surface specialist
  I want protocol-specific assessment across mail transfer agents, real-time chat, and message brokers
  So that messaging candidates have scoped evidence, canary delivery follows explicit bounds, and inaccessible services are never reported as secure

  Scenario: Assessing mail, chat, and message broker services with protocol-specific collectors
    Given an approved target host exposing SMTP, POP3, IMAP, IRC, RabbitMQ, NATS, IBM MQ, Kafka, and MQTT
    When the messaging services assessment engine executes protocol-specific probes
    Then discrete assessments are recorded across mail transfer retrieval, realtime chat, and message broker streaming categories
    And observed configurations, authentication prerequisites, and versions are recorded for each service

  Scenario: Enforcing truth-in-advertising boundary where inaccessible services are never reported as secure
    Given a messaging service that is filtered, connection-refused, or timed out
    When the messaging services assessment probe executes
    Then the service exposure status is strictly recorded as "inaccessible"
    And the service is never marked as "protected" or "hardened"
    And authentication prerequisite is recorded as "unknown" with explicit uncertainty notes

  Scenario: Enforcing bounded message budget and preventing mass outbound relaying
    Given an assessment targeting mail and broker services with message budget 5
    When messaging service assessment probes execute against candidate brokers
    Then each assessment enforces a message budget of 5 messages
    And no outbound messages are sent by the synthetic or socket collectors

  Scenario: Validating an allowed synthetic canary and its fixture cleanup evidence
    Given an assessment configured with an allowed canary identifier "canary_mail_probe" and matching delivery and cleanup evidence
    When the messaging services assessment executes canary validation probes
    Then canary validation status is confirmed in the assessment record
    And a synthetic cleanup receipt with "synthetic_fixture_cleanup_confirmed" status and receipt hash is emitted

  Scenario: Rejecting a canary route outside the recipient or destination allowlist
    Given a canary delivery policy with an unauthorized recipient or destination
    When the messaging services assessment executes canary validation probes
    Then the canary request is rejected before any probe

  Scenario: Rejecting expired canary retention and exhausted message budget
    Given an expired canary policy or a synthetic fixture exceeding its message budget
    When the messaging services assessment executes canary validation probes
    Then no canary is validated and no cleanup receipt is emitted

  Scenario: Extracting messaging privilege candidates for unauthorized relay and broker takeover
    Given an evaluated target exhibiting open relay SMTP, user enumeration, guest RabbitMQ, unauthenticated NATS, and unauthenticated Kafka
    When messaging privilege candidates are extracted
    Then actionable candidates for "smtp_open_relay", "smtp_user_enumeration", "rabbitmq_guest_default_creds", "nats_unauthenticated_cluster", and "kafka_unauthenticated_broker" are generated
    And each candidate contains service type, target host, port, privilege impact, SHA-256 evidence hash, and remediation guidance

  Scenario: Reporting properly authenticated and hardened services as protected or remediated
    Given a hardened server enforcing SMTP STARTTLS, RabbitMQ auth, and Kafka SASL
    When the messaging services assessment evaluates access controls
    Then the exposure status is reported as "protected"
    And authentication prerequisites reflect "user_password" or "sasl"
    And zero unauthenticated messaging privilege candidates are generated
