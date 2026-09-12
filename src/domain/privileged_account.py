from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialRef:
    id: str

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("credential reference id cannot be empty")


@dataclass
class PrivilegedAccount:
    id: str
    target_id: str
    username: str
    credential_ref: CredentialRef
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("privileged account id cannot be empty")

        if not self.target_id.strip():
            raise ValueError("target id cannot be empty")

        if not self.username.strip():
            raise ValueError("username cannot be empty")
