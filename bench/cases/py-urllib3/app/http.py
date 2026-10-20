from urllib3.util.retry import Retry


def retry_policy():
    return Retry(
        total=3,
        backoff_factor=0.5,
        method_whitelist=frozenset(["GET", "HEAD"]),
        status_forcelist=[502, 503],
    )
