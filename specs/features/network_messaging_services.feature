Feature: Mail, Messaging, and Message Broker Services Assessment
  As an authorized penetration tester or attack surface specialist
  I want protocol-specific assessment across mail transfer agents, real-time chat, and message brokers
  So that messaging privilege candidates are routed to unauthorized relay or broker takeover workflows, canary messages generate verified cleanup receipts, bounded message budgets prevent mass outbound relaying, and inaccessible services are never falsely reported as secure

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
    And mass outbound relaying is prohibited and unconstrained bulk mail transmission is blocked

  Scenario: Validating boundary controls using canary messages and generating verified cleanup receipts
    Given an assessment configured with canary identifier "canary_mail_probe"
    When the messaging services assessment executes canary validation probes
    Then canary validation status is confirmed in the assessment record
    And a verified cleanup receipt with "verified_removed" status and receipt hash is emitted

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
