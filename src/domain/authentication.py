from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """The non-secret identity established by PAM-user authentication."""

    user_id: str
    username: str

    def __post_init__(self) -> None:
        if type(self.user_id) is not str or not self.user_id.strip():
            raise ValueError("principal user id cannot be empty")
        if type(self.username) is not str or not self.username.strip():
            raise ValueError("principal username cannot be empty")
