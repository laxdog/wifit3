"""Event log: bottom-left, bordered. A live ``RichLog`` (markup, scrolling) the
screen appends to as capture events land; the hard-won <40-char log lines mean
it narrates without ever needing to expand. The shell seeds it with demo lines
(no-target screenshots); a live target clears it and writes the real stream."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import RichLog

_COPY_MAX_LINES = 300   # OSC 52 (terminal clipboard) payloads get silently truncated/dropped by
                        # many terminals past a few tens of KB, especially over SSH/tmux -- a
                        # full session's log can run to thousands of lines, so copy only the most
                        # recent ones (almost always what's wanted for debugging anyway).


class LogBand(Vertical):
    def __init__(self, lines, **kwargs) -> None:
        super().__init__(**kwargs)
        self._initial = lines

    def compose(self) -> ComposeResult:
        yield RichLog(id="log-rich", markup=True, highlight=False, wrap=True)

    def on_mount(self) -> None:
        self.border_title = "LOG"
        log = self.query_one("#log-rich", RichLog)
        for line in self._initial:
            log.write(line)

    def write(self, renderable) -> None:
        self.query_one("#log-rich", RichLog).write(renderable)

    def clear(self) -> None:
        self.query_one("#log-rich", RichLog).clear()

    def get_text(self) -> str:
        """The last ``_COPY_MAX_LINES`` lines, plain text, right-trimmed (RichLog pads every
        Strip to the widget's full render width, which would otherwise bloat the payload)."""
        lines = self.query_one("#log-rich", RichLog).lines[-_COPY_MAX_LINES:]
        return "\n".join(strip.text.rstrip() for strip in lines)
