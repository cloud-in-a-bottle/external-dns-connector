"""The owner surface and the service surface must not be reachable from each other's identity.

These go through ``stack.app_url``, which bypasses the router, so the tests control the identity
headers directly. That is exactly the shape a request would take if the router's header handling
ever stopped being airtight, which is what makes it worth asserting on.
"""

import httpx
from openhost_test_harness import OpenhostStack

from .conftest import ZONE_A

CONSUMER_HEADERS = {
    "X-OpenHost-Consumer-Id": "some-app-id",
    "X-OpenHost-Consumer-Name": "some-app",
    "X-OpenHost-Permissions": '[{"grant":{"name":"**","type":"**","access":"rw"},"scope":"global"}]',
}
OWNER_HEADERS = {"X-OpenHost-Is-Owner": "true"}


def test_a_consumer_cannot_change_the_zone_set(stack: OpenhostStack, zones: list[str]) -> None:
    """The zone set is owner-only configuration; no grant, however broad, should reach it."""
    r = httpx.put(
        f"{stack.app_url}/api/zones",
        json={"zones": []},
        headers=CONSUMER_HEADERS,
        timeout=30,
    )
    assert r.status_code == 403, r.text[:300]

    # And the zones are still there.
    still = httpx.get(f"{stack.app_url}/", headers=OWNER_HEADERS, timeout=30).text
    assert ZONE_A in still


def test_a_consumer_cannot_reach_the_owner_pages(stack: OpenhostStack, zones: list[str]) -> None:
    for path in ("/", "/accounts", "/audit"):
        r = httpx.get(f"{stack.app_url}{path}", headers=CONSUMER_HEADERS, timeout=30)
        assert r.status_code == 403, f"{path} returned {r.status_code}"


def test_a_consumer_cannot_add_a_provider_account(stack: OpenhostStack, zones: list[str]) -> None:
    r = httpx.post(
        f"{stack.app_url}/accounts/add",
        data={"provider": "mock", "label": "sneaky"},
        headers=CONSUMER_HEADERS,
        timeout=30,
    )
    assert r.status_code == 403, r.text[:300]


def test_an_owner_session_cannot_use_the_service_api(stack: OpenhostStack, zones: list[str]) -> None:
    """Service routes act on behalf of a calling app; a bare owner session has no grants to check."""
    r = httpx.post(
        f"{stack.app_url}/api/dns/records/set",
        json={"zone": ZONE_A, "records": [{"name": "x", "type": "A", "ttl": 60, "data": "192.0.2.1"}]},
        headers=OWNER_HEADERS,
        timeout=30,
    )
    assert r.status_code == 403, r.text[:300]
    assert r.json()["error"] == "not_a_service_call"


def test_an_unauthenticated_request_reaches_nothing_but_health(stack: OpenhostStack, zones: list[str]) -> None:
    assert httpx.get(f"{stack.app_url}/health", timeout=30).status_code == 200
    for path in ("/", "/accounts", "/api/dns/zones"):
        r = httpx.get(f"{stack.app_url}{path}", timeout=30)
        assert r.status_code in (403, 405), f"{path} returned {r.status_code}"
