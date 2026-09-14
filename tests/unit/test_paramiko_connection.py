import re
from dataclasses import fields
from pathlib import Path

import paramiko
import pytest

import src.infrastructure.ssh.paramiko_connection as connection_module
from src.application.access_service import AccessResult
from src.domain.audit import AuditEvent
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.session import Session
from src.domain.target import Target
from src.infrastructure.ssh.errors import (
    HostKeyMismatchError,
    SshAuthenticationError,
    SshConnectionError,
)
from src.infrastructure.ssh.host_key import calculate_sha256_fingerprint
from src.infrastructure.ssh.paramiko_connection import (
    SSH_DISABLED_ALGORITHMS,
    ParamikoSshConnector,
    VerifiedSshConnection,
)
from src.ports.session_broker import BrokerCredential

CREDENTIAL_BYTES = b"temporary-ssh-test-credential"


class FakeSocket:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakeTransport:
    def __init__(
        self,
        server_key: paramiko.PKey,
        events: list[str],
        *,
        negotiation_error: Exception | None = None,
        authentication_error: Exception | None = None,
        authenticated: bool = True,
    ) -> None:
        self.server_key = server_key
        self.events = events
        self.negotiation_error = negotiation_error
        self.authentication_error = authentication_error
        self.authenticated = authenticated
        self.auth_calls = 0
        self.received_expected_password = False
        self.close_calls = 0
        self.disabled_algorithms: dict[str, tuple[str, ...]] | None = None

    def start_client(self, timeout: float) -> None:
        self.events.append("start_client")
        if self.negotiation_error is not None:
            raise self.negotiation_error

    def get_remote_server_key(self) -> paramiko.PKey:
        self.events.append("get_remote_server_key")
        return self.server_key

    def auth_password(self, username: str, password: str) -> None:
        self.events.append("auth_password")
        self.auth_calls += 1
        self.received_expected_password = (
            password == CREDENTIAL_BYTES.decode()
        )
        if self.authentication_error is not None:
            raise self.authentication_error

    def is_authenticated(self) -> bool:
        return self.authenticated

    def close(self) -> None:
        self.events.append("transport_close")
        self.close_calls += 1


def make_account() -> PrivilegedAccount:
    return PrivilegedAccount(
        id="account-001",
        target_id="target-001",
        username="root",
        credential_ref=CredentialRef("credential-001"),
    )


def make_target(server_key: paramiko.PKey) -> Target:
    return Target(
        id="target-001",
        name="test-server",
        host="server.example.test",
        port=22,
        expected_host_key=calculate_sha256_fingerprint(server_key),
    )


def install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    fake_socket: FakeSocket,
    fake_transport: FakeTransport,
    events: list[str],
) -> None:
    def create_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> FakeSocket:
        events.append("tcp_connect")
        return fake_socket

    def create_transport(
        connection_socket: FakeSocket,
        *,
        disabled_algorithms: dict[str, tuple[str, ...]],
    ) -> FakeTransport:
        events.append("transport_create")
        assert connection_socket is fake_socket
        fake_transport.disabled_algorithms = disabled_algorithms
        return fake_transport

    monkeypatch.setattr(
        connection_module.socket,
        "create_connection",
        create_connection,
    )
    monkeypatch.setattr(
        connection_module.paramiko,
        "Transport",
        create_transport,
    )


def test_matching_host_key_authenticates_and_returns_verified_connection(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    server_key = paramiko.RSAKey.generate(1024)
    fake_socket = FakeSocket()
    fake_transport = FakeTransport(server_key, events)
    install_fakes(monkeypatch, fake_socket, fake_transport, events)

    connection = ParamikoSshConnector().connect(
        make_target(server_key),
        make_account(),
        BrokerCredential(CREDENTIAL_BYTES),
    )

    assert isinstance(connection, VerifiedSshConnection)
    assert fake_transport.disabled_algorithms == dict(SSH_DISABLED_ALGORITHMS)
    assert fake_transport.auth_calls == 1
    assert fake_transport.received_expected_password is True
    assert events == [
        "tcp_connect",
        "transport_create",
        "start_client",
        "get_remote_server_key",
        "auth_password",
    ]


def test_algorithm_policy_leaves_only_expected_paramiko_5_algorithms():
    disabled = dict(SSH_DISABLED_ALGORITHMS)

    effective_ciphers = tuple(
        name
        for name in paramiko.Transport._preferred_ciphers
        if name not in disabled["ciphers"]
    )
    effective_macs = tuple(
        name
        for name in paramiko.Transport._preferred_macs
        if name not in disabled["macs"]
    )
    effective_keys = tuple(
        name
        for name in paramiko.Transport._preferred_keys
        if name not in disabled["keys"]
    )

    assert effective_ciphers == (
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    )
    assert effective_macs == (
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
    )
    assert effective_keys == (
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    )
    assert paramiko.Transport._preferred_kex == (
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha256",
    )


def test_host_key_mismatch_happens_before_authentication_and_closes_resources(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    server_key = paramiko.RSAKey.generate(1024)
    different_key = paramiko.RSAKey.generate(1024)
    fake_socket = FakeSocket()
    fake_transport = FakeTransport(server_key, events)
    install_fakes(monkeypatch, fake_socket, fake_transport, events)

    with pytest.raises(HostKeyMismatchError) as captured:
        ParamikoSshConnector().connect(
            make_target(different_key),
            make_account(),
            BrokerCredential(CREDENTIAL_BYTES),
        )

    assert fake_transport.auth_calls == 0
    assert CREDENTIAL_BYTES.decode() not in str(captured.value)
    assert "auth_password" not in events
    assert fake_transport.close_calls == 1
    assert fake_socket.close_calls == 1


def test_authentication_failure_is_translated_and_closes_resources(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    server_key = paramiko.RSAKey.generate(1024)
    fake_socket = FakeSocket()
    fake_transport = FakeTransport(
        server_key,
        events,
        authentication_error=paramiko.AuthenticationException(
            CREDENTIAL_BYTES.decode()
        ),
    )
    install_fakes(monkeypatch, fake_socket, fake_transport, events)

    with pytest.raises(SshAuthenticationError) as captured:
        ParamikoSshConnector().connect(
            make_target(server_key),
            make_account(),
            BrokerCredential(CREDENTIAL_BYTES),
        )

    assert CREDENTIAL_BYTES.decode() not in str(captured.value)
    assert fake_transport.close_calls == 1
    assert fake_socket.close_calls == 1


def test_invalid_credential_encoding_fails_before_authentication(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    server_key = paramiko.RSAKey.generate(1024)
    fake_socket = FakeSocket()
    fake_transport = FakeTransport(server_key, events)
    install_fakes(monkeypatch, fake_socket, fake_transport, events)

    with pytest.raises(
        SshAuthenticationError,
        match="SSH credential encoding is invalid",
    ):
        ParamikoSshConnector().connect(
            make_target(server_key),
            make_account(),
            BrokerCredential(bytes([0xFF, 0xFE])),
        )

    assert fake_transport.auth_calls == 0
    assert fake_transport.close_calls == 1
    assert fake_socket.close_calls == 1


def test_tcp_connection_failure_is_translated(
    monkeypatch: pytest.MonkeyPatch,
):
    def fail_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> None:
        raise OSError("controlled connection failure")

    monkeypatch.setattr(
        connection_module.socket,
        "create_connection",
        fail_connection,
    )

    with pytest.raises(
        SshConnectionError,
        match="SSH TCP connection failed for target target-001",
    ):
        server_key = paramiko.RSAKey.generate(1024)
        ParamikoSshConnector().connect(
            make_target(server_key),
            make_account(),
            BrokerCredential(CREDENTIAL_BYTES),
        )


def test_negotiation_failure_closes_transport_and_socket(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    server_key = paramiko.RSAKey.generate(1024)
    fake_socket = FakeSocket()
    fake_transport = FakeTransport(
        server_key,
        events,
        negotiation_error=paramiko.SSHException(
            "controlled negotiation failure"
        ),
    )
    install_fakes(monkeypatch, fake_socket, fake_transport, events)

    with pytest.raises(
        SshConnectionError,
        match="SSH negotiation failed for target target-001",
    ) as captured:
        ParamikoSshConnector().connect(
            make_target(server_key),
            make_account(),
            BrokerCredential(CREDENTIAL_BYTES),
        )

    assert fake_transport.disabled_algorithms == dict(SSH_DISABLED_ALGORITHMS)
    assert fake_transport.auth_calls == 0
    assert "auth_password" not in events
    assert "controlled negotiation failure" not in str(captured.value)
    assert CREDENTIAL_BYTES.decode() not in str(captured.value)
    assert fake_transport.close_calls == 1
    assert fake_socket.close_calls == 1


def test_explicit_close_is_idempotent_and_closes_owned_resources(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    server_key = paramiko.RSAKey.generate(1024)
    fake_socket = FakeSocket()
    fake_transport = FakeTransport(server_key, events)
    install_fakes(monkeypatch, fake_socket, fake_transport, events)
    connection = ParamikoSshConnector().connect(
        make_target(server_key),
        make_account(),
        BrokerCredential(CREDENTIAL_BYTES),
    )

    connection.close()
    connection.close()

    assert fake_transport.close_calls == 1
    assert fake_socket.close_calls == 1


def test_connection_context_manager_closes_owned_resources(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    server_key = paramiko.RSAKey.generate(1024)
    fake_socket = FakeSocket()
    fake_transport = FakeTransport(server_key, events)
    install_fakes(monkeypatch, fake_socket, fake_transport, events)

    with ParamikoSshConnector().connect(
        make_target(server_key),
        make_account(),
        BrokerCredential(CREDENTIAL_BYTES),
    ):
        pass

    assert fake_transport.close_calls == 1
    assert fake_socket.close_calls == 1


def test_connection_repr_and_attributes_do_not_expose_credential(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    server_key = paramiko.RSAKey.generate(1024)
    fake_socket = FakeSocket()
    fake_transport = FakeTransport(server_key, events)
    install_fakes(monkeypatch, fake_socket, fake_transport, events)
    connection = ParamikoSshConnector().connect(
        make_target(server_key),
        make_account(),
        BrokerCredential(CREDENTIAL_BYTES),
    )

    assert CREDENTIAL_BYTES.decode() not in repr(connection)
    assert all("credential" not in name for name in connection.__slots__)
    connection.close()


def test_ssh_source_has_no_tofu_logging_or_boundary_leaks():
    project_root = Path(__file__).parents[2]
    ssh_source = "\n".join(
        path.read_text()
        for path in (project_root / "src/infrastructure/ssh").glob("*.py")
    )
    domain_application_source = "\n".join(
        path.read_text()
        for package in ("domain", "application")
        for path in (project_root / f"src/{package}").glob("*.py")
    )

    assert "AutoAddPolicy" not in ssh_source
    assert "set_missing_host_key_policy" not in ssh_source
    assert re.search(r"\bprint\s*\(", ssh_source) is None
    assert "logging" not in ssh_source
    assert "paramiko" not in domain_application_source


def test_existing_public_models_have_no_credential_fields():
    forbidden_names = {
        "password",
        "secret",
        "credential",
        "master_key",
        "token",
        "private_key",
    }

    for model in (AccessResult, AuditEvent, Session):
        field_names = {field.name for field in fields(model)}
        assert field_names.isdisjoint(forbidden_names)
