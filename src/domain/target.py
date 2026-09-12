from dataclasses import dataclass


@dataclass(frozen=True)
class HostKeyFingerprint:
    value: str

    def __post_init__(self) -> None:
        if not self.value.startswith("SHA256:"):
            raise ValueError(
                "SSH host key fingerprint must start with 'SHA256:'"
            )


@dataclass
class Target:
    id: str
    name: str
    host: str
    port: int
    expected_host_key: HostKeyFingerprint
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("target id cannot be empty")

        if not self.name.strip():
            raise ValueError("target name cannot be empty")

        if not self.host.strip():
            raise ValueError("target host cannot be empty")

        if not 1 <= self.port <= 65535:
            raise ValueError("target port must be between 1 and 65535")
