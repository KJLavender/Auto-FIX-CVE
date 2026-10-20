from app.http import retry_policy


def test_retries_idempotent_requests_on_gateway_errors():
    policy = retry_policy()
    assert policy.total == 3
    assert policy.is_retry("GET", 503)
    assert not policy.is_retry("POST", 503)
