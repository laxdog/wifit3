"""Generic captive-portal page templates: every template renders, escapes the SSID, and POSTs."""
import pytest

from wifit3.net.portal_templates import PortalTemplate, render

_SSID = "Coffee & Wifi <Free>"


@pytest.mark.parametrize("template", list(PortalTemplate))
def test_every_template_renders_a_form_that_posts(template):
    html = render(template, "TestNet")
    assert html.startswith("<!doctype html>")
    assert '<form method="post">' in html
    assert "<title>TestNet - Sign in</title>" in html


def test_ssid_is_html_escaped():
    html = render(PortalTemplate.PASSWORD, _SSID)
    assert "<Free>" not in html
    assert "&lt;Free&gt;" in html


def test_password_template_has_no_email_field():
    html = render(PortalTemplate.PASSWORD, "TestNet")
    assert 'name="password"' in html and 'name="email"' not in html


def test_login_template_has_both_fields():
    html = render(PortalTemplate.LOGIN, "TestNet")
    assert 'name="email"' in html and 'name="password"' in html


def test_clickthrough_template_requires_agreement_not_a_password():
    html = render(PortalTemplate.CLICKTHROUGH, "TestNet")
    assert 'name="agree"' in html and 'name="password"' not in html
