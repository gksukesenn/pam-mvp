import socket

import paramiko

from src.domain.privileged_account import PrivilegedAccount
from src.domain.target import Target
from src.infrastructure.ssh.errors import (
    HostKeyMismatchError,
    SshAuthenticationError,
    SshConnectionError,
)
from src.infrastructure.ssh.host_key import verify_pinned_host_key
from src.ports.access_dependencies import BrokerCredential


class VerifiedSshConnection:
    __slots__ = ("_transport", "_socket", "_closed")

    def __init__(
        self,
        transport: paramiko.Transport,
        connection_socket: socket.socket,
    ) -> None:
        self._transport = transport
        self._socket = connection_socket
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._transport.close()
        finally:
            self._socket.close()

    def __enter__(self) -> "VerifiedSshConnection":
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"VerifiedSshConnection(closed={self._closed})"

    def _open_session_channel(self) -> paramiko.Channel:
        if self._closed:
            raise SshConnectionError("verified SSH connection is closed")
        return self._transport.open_session()


class ParamikoSshConnector:
    def __init__(self, connect_timeout: float = 10.0) -> None:
        self._connect_timeout = connect_timeout

    def connect(
        self,
        target: Target,
        account: PrivilegedAccount,
        credential: BrokerCredential,
    ) -> VerifiedSshConnection:
        connection_socket: socket.socket | None = None
        transport: paramiko.Transport | None = None

        try:
            connection_socket = socket.create_connection(
                (target.host, target.port),
                timeout=self._connect_timeout,
            )
        except OSError as error:
            raise SshConnectionError(
                f"SSH TCP connection failed for target {target.id}"
            ) from error

        try:
            transport = paramiko.Transport(connection_socket)
            transport.start_client(timeout=self._connect_timeout)
            server_key = transport.get_remote_server_key()
        except Exception as error:
            self._close_resources(transport, connection_socket)
            raise SshConnectionError(
                f"SSH negotiation failed for target {target.id}"
            ) from error

        try:
            verify_pinned_host_key(target, server_key)
        except HostKeyMismatchError:
            self._close_resources(transport, connection_socket)
            raise
        except Exception:
            self._close_resources(transport, connection_socket)
            raise SshConnectionError(
                f"SSH host key verification failed for target {target.id}"
            ) from None

        try:
            self._authenticate(transport, account, credential)
        except SshAuthenticationError:
            self._close_resources(transport, connection_socket)
            raise
        except Exception:
            self._close_resources(transport, connection_socket)
            raise SshAuthenticationError(
                "SSH authentication failed"
            ) from None

        return VerifiedSshConnection(transport, connection_socket)

    @staticmethod
    def _authenticate(
        transport: paramiko.Transport,
        account: PrivilegedAccount,
        credential: BrokerCredential,
    ) -> None:
        try:
            password = credential.as_bytes().decode("utf-8")
        except UnicodeDecodeError:
            raise SshAuthenticationError(
                "SSH credential encoding is invalid"
            ) from None

        try:
            transport.auth_password(
                username=account.username,
                password=password,
            )
        except (OSError, paramiko.SSHException):
            password = None
            raise SshAuthenticationError("SSH authentication failed") from None
        password = None

        if not transport.is_authenticated():
            raise SshAuthenticationError("SSH authentication failed")

    @staticmethod
    def _close_resources(
        transport: paramiko.Transport | None,
        connection_socket: socket.socket | None,
    ) -> None:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        if connection_socket is not None:
            try:
                connection_socket.close()
            except Exception:
                pass
