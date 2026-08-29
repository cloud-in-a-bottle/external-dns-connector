"""End-to-end tests of the DNS service through the real OpenHost router.

These deploy a real consumer app and call through the router's service proxy, so the identity and
permission headers the app trusts are the ones the router actually produces — not forged ones.
"""

import pytest
from openhost_test_harness import OpenhostStack
from openhost_test_harness import ServiceConsumer

from .conftest import SERVICE_URL
from .conftest import ZONE_A
from .conftest import ZONE_B

ACME_GRANT = {"name": "_acme-challenge.**", "type": "TXT", "access": "rw"}
READ_ALL_GRANT = {"name": "**", "type": "**", "access": "r"}
WRITE_ALL_GRANT = {"name": "**", "type": "**", "access": "rw"}


@pytest.fixture(scope="module")
def acme_app(stack: OpenhostStack, zones: list[str]) -> ServiceConsumer:
    """A consumer holding only a narrow TXT grant, granted at install from its manifest."""
    return stack.deploy_service_consumer(
        SERVICE_URL,
        shortname="dns",
        version=">=0.1.0",
        name="consumer-acme",
        grants=[ACME_GRANT],
        grant_manifest_permissions=True,
    )


@pytest.fixture(scope="module")
def admin_app(stack: OpenhostStack, zones: list[str]) -> ServiceConsumer:
    """A consumer with full write access, used to seed records the narrow app should not see."""
    return stack.deploy_service_consumer(
        SERVICE_URL,
        shortname="dns",
        version=">=0.1.0",
        name="consumer-admin",
        grants=[WRITE_ALL_GRANT],
        grant_manifest_permissions=True,
    )


def test_write_and_read_back_within_grant(acme_app: ServiceConsumer) -> None:
    r = acme_app.call(
        "records/set",
        {"zone": ZONE_A, "records": [{"name": "_acme-challenge.www", "type": "TXT", "ttl": 60, "data": "token-1"}]},
    )
    assert r.status == 200, r.body
    assert r.body["ok"] is True

    r = acme_app.call("records/get", {"zone": ZONE_A, "name": "_acme-challenge.www"})
    assert r.status == 200, r.body
    records = r.body["results"][0]["records"]
    assert [rec["data"] for rec in records] == ["token-1"]


def test_write_outside_grant_is_refused(acme_app: ServiceConsumer) -> None:
    r = acme_app.call(
        "records/set",
        {"zone": ZONE_A, "records": [{"name": "home", "type": "A", "ttl": 300, "data": "192.0.2.1"}]},
    )
    assert r.status == 403, r.body
    assert r.body["error"] == "permission_required"
    assert r.body["required_grant"]["grant"] == {"name": "home", "type": "A", "access": "rw"}
    # The router recognises the global scope and attaches its own owner-facing approval link.
    assert "grant_url" in r.body["required_grant"], r.body


def test_reads_are_filtered_to_granted_records(acme_app: ServiceConsumer, admin_app: ServiceConsumer) -> None:
    seeded = admin_app.call(
        "records/set",
        {
            "zone": ZONE_A,
            "records": [
                {"name": "_acme-challenge.filtered", "type": "TXT", "ttl": 60, "data": "visible"},
                {"name": "secret", "type": "A", "ttl": 60, "data": "192.0.2.9"},
                {"name": "@", "type": "MX", "ttl": 60, "data": "10 mail.example.test."},
            ],
        },
    )
    assert seeded.status == 200, seeded.body

    r = acme_app.call("records/get", {"zone": ZONE_A})
    assert r.status == 200, r.body
    names = {rec["name"] for rec in r.body["results"][0]["records"]}
    assert "secret" not in names, "an app saw a record outside its grant"
    assert all(n.startswith("_acme-challenge.") for n in names), names


def test_partially_permitted_batch_writes_nothing(acme_app: ServiceConsumer) -> None:
    r = acme_app.call(
        "records/set",
        {
            "zone": ZONE_A,
            "records": [
                {"name": "_acme-challenge.batch", "type": "TXT", "ttl": 60, "data": "allowed"},
                {"name": "batch", "type": "A", "ttl": 60, "data": "192.0.2.2"},
            ],
        },
    )
    assert r.status == 403, r.body

    check = acme_app.call("records/get", {"zone": ZONE_A, "name": "_acme-challenge.batch"})
    assert check.body["results"][0]["records"] == [], "the permitted half of a refused batch was applied"


def test_zone_is_required_on_writes(acme_app: ServiceConsumer) -> None:
    r = acme_app.call(
        "records/set",
        {"records": [{"name": "_acme-challenge.x", "type": "TXT", "ttl": 60, "data": "x"}]},
    )
    assert r.status == 400, r.body
    assert r.body["error"] == "zone_required"


def test_unknown_zone_is_rejected(acme_app: ServiceConsumer) -> None:
    r = acme_app.call(
        "records/set",
        {"zone": "nope.invalid", "records": [{"name": "_acme-challenge.x", "type": "TXT", "ttl": 60, "data": "x"}]},
    )
    assert r.status == 400, r.body
    assert r.body["error"] == "unknown_zone"


def test_wildcard_zone_fans_out(acme_app: ServiceConsumer) -> None:
    r = acme_app.call(
        "records/set",
        {"zone": "*", "records": [{"name": "_acme-challenge.fan", "type": "TXT", "ttl": 60, "data": "fanned"}]},
    )
    assert r.status == 200, r.body
    assert {res["zone"] for res in r.body["results"]} == {ZONE_A, ZONE_B}
    assert all(res["ok"] for res in r.body["results"]), r.body

    for zone in (ZONE_A, ZONE_B):
        got = acme_app.call("records/get", {"zone": zone, "name": "_acme-challenge.fan"})
        assert [rec["data"] for rec in got.body["results"][0]["records"]] == ["fanned"], (zone, got.body)


def test_delete_removes_the_record(acme_app: ServiceConsumer) -> None:
    rec = {"name": "_acme-challenge.gone", "type": "TXT", "ttl": 60, "data": "temporary"}
    assert acme_app.call("records/set", {"zone": ZONE_A, "records": [rec]}).status == 200

    r = acme_app.call("records/delete", {"zone": ZONE_A, "records": [rec]})
    assert r.status == 200, r.body

    got = acme_app.call("records/get", {"zone": ZONE_A, "name": "_acme-challenge.gone"})
    assert got.body["results"][0]["records"] == []


def test_zone_listing_without_a_grant_is_empty(
    stack: OpenhostStack, zones: list[str], acme_app: ServiceConsumer
) -> None:
    granted = acme_app.call("zones", None)
    assert granted.status == 200, granted.body
    assert sorted(granted.body["zones"]) == sorted([ZONE_A, ZONE_B])

    ungranted = stack.deploy_service_consumer(
        SERVICE_URL, shortname="dns", version=">=0.1.0", name="consumer-nogrants"
    )
    empty = ungranted.call("zones", None)
    assert empty.status == 200, empty.body
    assert empty.body["zones"] == []

    # And the same app starts seeing zones once the owner grants it read access.
    stack.grant(ungranted.app_id, SERVICE_URL, READ_ALL_GRANT)
    allowed = ungranted.call("zones", None)
    assert allowed.status == 200, allowed.body
    assert sorted(allowed.body["zones"]) == sorted([ZONE_A, ZONE_B])


def test_clearing_an_rrset_needs_no_knowledge_of_its_contents(acme_app: ServiceConsumer) -> None:
    """The cleanup case: a run that crashed before recording its token can still wipe the name."""
    for token in ("stale-one", "stale-two"):
        assert (
            acme_app.call(
                "records/append",
                {"zone": ZONE_A, "records": [{"name": "_acme-challenge.crashed", "type": "TXT", "ttl": 60, "data": token}]},
            ).status
            == 200
        )

    cleared = acme_app.call(
        "records/delete",
        {"zone": ZONE_A, "records": [{"name": "_acme-challenge.crashed", "type": "TXT"}]},
    )
    assert cleared.status == 200, cleared.body
    assert len(cleared.body["results"][0]["records"]) == 2, cleared.body

    got = acme_app.call("records/get", {"zone": ZONE_A, "name": "_acme-challenge.crashed"})
    assert got.body["results"][0]["records"] == [], got.body

    # Safe to run unconditionally: clearing a name that holds nothing is a no-op, not an error.
    again = acme_app.call(
        "records/delete",
        {"zone": ZONE_A, "records": [{"name": "_acme-challenge.crashed", "type": "TXT"}]},
    )
    assert again.status == 200, again.body
    assert again.body["results"][0]["records"] == []


def test_clearing_an_rrset_outside_the_grant_is_refused(acme_app: ServiceConsumer) -> None:
    r = acme_app.call("records/delete", {"zone": ZONE_A, "records": [{"name": "home", "type": "A"}]})
    assert r.status == 403, r.body
    assert r.body["error"] == "permission_required"
