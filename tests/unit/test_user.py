import pytest

from src.domain.user import User


def test_user_can_be_created():
    user = User(
        id="user-001",
        username="goksu",
    )

    assert user.id == "user-001"
    assert user.username == "goksu"
    assert user.is_active is True


def test_user_rejects_empty_username():
    with pytest.raises(ValueError, match="username cannot be empty"):
        User(
            id="user-001",
            username="",
        )
