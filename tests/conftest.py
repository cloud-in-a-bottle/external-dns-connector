from collections.abc import Iterator

import pytest
from openhost_test_harness import OpenhostStack

SERVICE_URL = "github.com/cloud-in-a-bottle/external-dns-connector/services/dns"

ZONE_A = "example.test"
ZONE_B = "other.test"


@pytest.fixture(scope="session")
def stack() -> Iterator[OpenhostStack]:
    """Build the Dockerfile, run the app under podman per cloudinabottle.toml, and front it with the
    real OpenHost router.

    - stack.url                    — through the router; requires owner auth
    - stack.owner_session          — a requests.Session authenticated as the zone owner
    - stack.playwright_login(page) — log a playwright page in as the owner
    - stack.app_url                — direct to the container, bypassing the router
    """
    with OpenhostStack() as s:
        yield s


@pytest.fixture(scope="session")
def zones(stack: OpenhostStack) -> list[str]:
    """Configure a mock provider account and two zones through the real owner-facing forms.

    Uses the built-in mock provider so the record path is exercised end to end without credentials
    for a real registrar.
    """
    r = stack.owner_session.post(
        f"{stack.url}/accounts/add",
        data={"provider": "mock", "label": "test-mock"},
        timeout=30,
    )
    assert r.status_code == 200, f"adding the mock account failed: {r.status_code} {r.text[:300]}"

    accounts = stack.owner_session.get(f"{stack.url}/accounts", timeout=30)
    assert "test-mock" in accounts.text, "the mock account is not listed after being added"

    account_id = _account_id(stack)
    r = stack.owner_session.put(
        f"{stack.url}/api/zones",
        json={"zones": [{"zone": ZONE_A, "account_id": account_id}, {"zone": ZONE_B, "account_id": account_id}]},
        timeout=30,
    )
    assert r.status_code == 200, f"setting zones failed: {r.status_code} {r.text[:300]}"
    assert sorted(r.json()["zones"]) == sorted([ZONE_A, ZONE_B])
    return [ZONE_A, ZONE_B]


def _account_id(stack: OpenhostStack) -> int:
    """Read the mock account's id out of the delete form on the accounts page.

    The app has no owner-facing JSON listing for accounts, and inventing one just for tests would
    mean testing a route no real client uses.
    """
    import re

    html = stack.owner_session.get(f"{stack.url}/accounts", timeout=30).text
    ids = re.findall(r'name="id" value="(\d+)"', html)
    assert ids, f"no account id found on the accounts page: {html[:500]}"
    return int(ids[0])
