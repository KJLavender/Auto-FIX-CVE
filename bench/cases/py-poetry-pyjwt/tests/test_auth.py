import pytest

from app.auth import issue, user_from


def test_round_trip():
    token = issue("user-42", "a-long-enough-shared-secret-value")
    assert isinstance(token, str)
    assert user_from(token, "a-long-enough-shared-secret-value") == "user-42"


def test_rejects_other_secret():
    token = issue("user-42", "a-long-enough-shared-secret-value")
    with pytest.raises(Exception):
        user_from(token, "some-other-secret-value-entirely")
