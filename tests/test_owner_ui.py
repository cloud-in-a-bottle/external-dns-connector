import httpx
import requests
from openhost_test_harness import OpenhostStack
from playwright.sync_api import Page
from playwright.sync_api import expect

from .conftest import ZONE_A


def test_health_is_reachable_without_auth(stack: OpenhostStack) -> None:
    """The router probes /health directly on the container, so it must not require an identity."""
    r = httpx.get(f"{stack.app_url}/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_ui_is_login_gated(stack: OpenhostStack) -> None:
    r = requests.get(f"{stack.url}/", allow_redirects=False, timeout=10)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_owner_can_browse_and_edit_records(stack: OpenhostStack, zones: list[str], page: Page) -> None:
    stack.playwright_login(page)
    page.goto(stack.url)
    expect(page.get_by_role("heading", name="Zones")).to_be_visible()
    expect(page.get_by_role("cell", name=ZONE_A, exact=True)).to_be_visible()

    page.goto(f"{stack.url}/zones/{ZONE_A}")
    page.fill("#name", "ui-added")
    page.select_option("#type", "A")
    page.fill("#ttl", "300")
    page.fill("#data", "192.0.2.50")
    page.click("button:has-text('Add')")

    row = page.locator("table tbody tr", has=page.get_by_role("cell", name="ui-added", exact=True))
    expect(row).to_have_count(1)
    expect(row.get_by_role("cell", name="192.0.2.50", exact=True)).to_be_visible()


def test_owner_sees_an_invalid_record_rejected(stack: OpenhostStack, zones: list[str], page: Page) -> None:
    stack.playwright_login(page)
    page.goto(f"{stack.url}/zones/{ZONE_A}")
    page.fill("#name", "bad")
    page.select_option("#type", "A")
    page.fill("#ttl", "300")
    page.fill("#data", "not-an-ip-address")
    page.click("button:has-text('Add')")

    expect(page.locator(".flash.bad")).to_be_visible()


def test_owner_pages_render(stack: OpenhostStack, zones: list[str], page: Page) -> None:
    stack.playwright_login(page)
    for path, heading in [
        ("/accounts", "DNS providers"),
        ("/audit", "Activity"),
    ]:
        page.goto(f"{stack.url}{path}")
        expect(page.get_by_role("heading", name=heading)).to_be_visible()


def test_record_changes_appear_in_the_activity_log(stack: OpenhostStack, zones: list[str], page: Page) -> None:
    stack.playwright_login(page)
    page.goto(f"{stack.url}/audit")
    expect(page.get_by_text("zones_replace")).to_be_visible()


def test_provider_credentials_are_never_rendered_back(stack: OpenhostStack, zones: list[str]) -> None:
    """A secret typed into the provider form must not come back out in any owner page."""
    label = "Hetzner credential secrecy check"
    token = "synthetic-hetzner-api-token-for-secrecy-test"
    r = stack.owner_session.post(
        f"{stack.url}/accounts/add",
        data={"provider": "hetzner", "label": label, "api_token": token},
        timeout=30,
    )
    assert r.status_code == 200, r.text[:300]
    assert f"<td>{label}</td>" in r.text, "the Hetzner account is not listed after being added"

    for path in ("/accounts", "/", "/audit"):
        body = stack.owner_session.get(f"{stack.url}{path}", timeout=30).text
        assert token not in body, f"the API token leaked into {path}"
