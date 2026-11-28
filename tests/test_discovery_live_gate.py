"""Regression coverage for discovery live-mode admission boundaries."""

from argparse import Namespace
from unittest.mock import patch

import pytest

from cops.discovery.cli import (
    command_active_discovery,
    command_data_discovery,
    command_developer_discovery,
    command_discovery,
    command_infra_discovery,
    command_legacy_discovery,
    command_messaging_discovery,
    command_remote_discovery,
)
from cops.discovery.data_collector import StandardSocketDataCollector, assess_data_services
from cops.discovery.developer_collector import StandardSocketDeveloperCollector, assess_developer_services
from cops.discovery.developer_destinations import DeveloperDestinationPolicy
from cops.discovery.infra_collector import StandardSocketInfraCollector, assess_infrastructure_services
from cops.discovery.legacy_collector import StandardSocketLegacyCollector, assess_legacy_services
from cops.discovery.messaging_collector import StandardSocketMessagingCollector, assess_messaging_services
from cops.discovery.remote_collector import StandardSocketRemoteCollector, assess_remote_services


def test_active_live_scan_and_resume_rejected_before_input_or_dispatch():
    for command in ("scan", "resume"):
        with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
            command_active_discovery(Namespace(active_command=command, mode="live"))


@pytest.mark.parametrize("family", ["infrastructure", "remote", "data", "messaging", "developer", "legacy"])
def test_service_family_live_mode_rejected_before_dispatch(family):
    with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
        command_discovery(Namespace(discovery_command=family, mode="live"))


@pytest.mark.parametrize(
    "handler",
    [
        command_infra_discovery,
        command_remote_discovery,
        command_data_discovery,
        command_messaging_discovery,
        command_developer_discovery,
        command_legacy_discovery,
    ],
)
def test_direct_service_cli_handlers_reject_live_before_collector_construction(handler):
    with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
        handler(Namespace(mode="live"))


@pytest.mark.parametrize(
    ("assessment", "collector"),
    [
        (assess_infrastructure_services, StandardSocketInfraCollector()),
        (assess_remote_services, StandardSocketRemoteCollector()),
        (assess_data_services, StandardSocketDataCollector()),
        (assess_messaging_services, StandardSocketMessagingCollector()),
        (assess_developer_services, StandardSocketDeveloperCollector(DeveloperDestinationPolicy())),
        (assess_legacy_services, StandardSocketLegacyCollector()),
    ],
)
def test_public_assessment_runners_reject_socket_collectors(assessment, collector):
    with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
        assessment(["127.0.0.1"], collector=collector)


@pytest.mark.parametrize(
    "assessment",
    [
        assess_infrastructure_services,
        assess_remote_services,
        assess_data_services,
        assess_messaging_services,
        assess_developer_services,
        assess_legacy_services,
    ],
)
def test_public_assessment_runners_reject_unmarked_custom_collectors(assessment):
    class UnmarkedCollector:
        def resolve_target(self, target):
            raise AssertionError("resolve_target must not be called")

        def probe_service(self, *args, **kwargs):
            raise AssertionError("probe_service must not be called")

    with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
        assessment(["127.0.0.1"], collector=UnmarkedCollector())


@pytest.mark.parametrize(
    ("collector", "service_type"),
    [
        (StandardSocketInfraCollector(), "dns"),
        (StandardSocketRemoteCollector(), "ssh"),
        (StandardSocketDataCollector(), "postgresql"),
        (StandardSocketMessagingCollector(), "smtp"),
        (StandardSocketDeveloperCollector(DeveloperDestinationPolicy()), "docker"),
        (StandardSocketLegacyCollector(), "ndmp"),
    ],
)
def test_direct_socket_collector_methods_fail_before_dns_or_connect(collector, service_type):
    with (
        patch("socket.gethostbyname") as resolve,
        patch("socket.create_connection") as connect,
        patch("socket.socket") as udp_socket,
    ):
        with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
            collector.resolve_target("127.0.0.1")
        with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
            collector.probe_service("127.0.0.1", "127.0.0.1", service_type, 80)
    resolve.assert_not_called()
    connect.assert_not_called()
    udp_socket.assert_not_called()


@pytest.mark.parametrize("dispatcher_method", ["resolve_target", "dispatch_probe", "_dispatch_udp"])
def test_public_standard_dispatcher_methods_fail_before_network_io(dispatcher_method):
    from cops.discovery.active_scanner import StandardSocketDispatcher

    dispatcher = StandardSocketDispatcher()
    with (
        patch("socket.getaddrinfo") as resolve,
        patch("socket.create_connection") as connect,
        patch("socket.socket") as udp_socket,
        patch("os.urandom") as entropy,
    ):
        with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
            if dispatcher_method == "resolve_target":
                dispatcher.resolve_target("127.0.0.1")
            elif dispatcher_method == "dispatch_probe":
                dispatcher.dispatch_probe("127.0.0.1", "127.0.0.1", 80)
            else:
                dispatcher._dispatch_udp("127.0.0.1", "127.0.0.1", 53, 0.1, "external")
    resolve.assert_not_called()
    connect.assert_not_called()
    udp_socket.assert_not_called()
    entropy.assert_not_called()


def test_effect_classification_flags_do_not_authorize_socket_execution():
    developer = StandardSocketDeveloperCollector(
        DeveloperDestinationPolicy(),
        allow_code_execution=True,
        allow_state_change=True,
    )
    legacy = StandardSocketLegacyCollector(allow_code_execution=True, allow_state_change=True)
    for collector in (developer, legacy):
        with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
            collector.probe_service("127.0.0.1", "127.0.0.1", "example", 80)
