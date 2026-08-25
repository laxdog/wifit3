"""portal_assets: extracting a cloned page's own local <img>/<link>/<script> references."""
from wifit3.net.portal_assets import extract_asset_refs, guess_content_type


def test_extracts_relative_link_and_img_and_script_src():
    html = ('<link rel="stylesheet" href="/splash.css">'
           '<img src="/images/splash.jpg">'
           '<script src="/app.js"></script>')
    assert extract_asset_refs(html) == {"/splash.css", "/images/splash.jpg", "/app.js"}


def test_normalizes_absolute_http_url_to_its_path():
    html = '<img src="http://status.client/images/splash.jpg">'
    assert extract_asset_refs(html) == {"/images/splash.jpg"}


def test_unescapes_html_entity_encoded_slashes_before_parsing():
    """A real openNDS page renders href="http:&#47;&#47;status.client/splash.css" -- without
    unescaping first, urlsplit can't see the "//" and mis-parses the whole thing as one path."""
    html = '<link rel="stylesheet" href="http:&#47;&#47;status.client/splash.css">'
    assert extract_asset_refs(html) == {"/splash.css"}


def test_adds_leading_slash_to_a_bare_relative_reference():
    html = '<link href="splash.css">'
    assert extract_asset_refs(html) == {"/splash.css"}


def test_skips_https_data_and_protocol_relative_refs():
    html = ('<img src="https://cdn.example.com/logo.png">'
           '<img src="data:image/png;base64,abcd">'
           '<script src="//cdn.example.com/lib.js"></script>')
    assert extract_asset_refs(html) == set()


def test_no_refs_in_a_plain_page():
    assert extract_asset_refs("<html><body>hi</body></html>") == set()


def test_guess_content_type_matches_known_extensions():
    assert guess_content_type("/splash.css") == "text/css"
    assert guess_content_type("/images/splash.jpg") == "image/jpeg"
    assert guess_content_type("/icon.ico") == "image/x-icon"


def test_guess_content_type_falls_back_for_unknown_extension():
    assert guess_content_type("/data.bin") == "application/octet-stream"
