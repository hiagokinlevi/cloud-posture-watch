import re

from cloud_posture_watch_cli import main


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def test_no_color_flag_disables_ansi_sequences(capsys):
    rc = main(["--no-color"])
    assert rc == 0

    out = capsys.readouterr().out
    assert "scan complete" in out
    assert ANSI_RE.search(out) is None
