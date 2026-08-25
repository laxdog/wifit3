"""LogBand.get_text(): what 'copy the log' (screen.py's 'y' binding) puts on the clipboard.
Capped and right-trimmed -- a full session's log can run to thousands of lines, and RichLog pads
every line out to the widget's render width, both of which risk tripping a terminal's OSC 52
clipboard payload size limit (confirmed live: an uncapped, unstripped copy got silently truncated
down to a single fragment)."""
from textual.app import App

from wifit3.ui.screens.focus_v2.log_band import LogBand, _COPY_MAX_LINES


class _Host(App):
    def compose(self):
        yield LogBand([])


async def test_get_text_joins_written_lines():
    async with _Host().run_test() as pilot:
        band = pilot.app.query_one(LogBand)
        band.write("first line")
        band.write("second line")
        await pilot.pause()
        text = band.get_text()
        assert "first line" in text and "second line" in text
        assert text.index("first line") < text.index("second line")


async def test_get_text_strips_trailing_render_width_padding():
    """RichLog pads every Strip out to the widget's full render width with blank space; a short
    log line must not carry that padding into the copied text."""
    async with _Host().run_test() as pilot:
        band = pilot.app.query_one(LogBand)
        band.write("short")
        await pilot.pause()
        text = band.get_text()
        assert text == "short"


async def test_get_text_caps_to_the_most_recent_lines():
    async with _Host().run_test() as pilot:
        band = pilot.app.query_one(LogBand)
        total = _COPY_MAX_LINES + 50
        for i in range(total):
            band.write(f"line {i}")
        await pilot.pause()
        text = band.get_text()
        lines = text.split("\n")
        assert len(lines) == _COPY_MAX_LINES
        assert lines[0] == f"line {total - _COPY_MAX_LINES}"     # oldest kept
        assert lines[-1] == f"line {total - 1}"                  # newest
        assert "line 0" not in text                              # dropped: too old
