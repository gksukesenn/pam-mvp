from dataclasses import dataclass


@dataclass
class User:
    id: str
    username: str
    is_active: bool = True

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("user id cannot be empty")

        if not self.username.strip():
            raise ValueError("username cannot be empty")
