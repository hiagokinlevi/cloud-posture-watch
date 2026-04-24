import cloud_posture_watch_cli as cli


def test_version_flag_prints_version_and_exits(monkeypatch, capsys):
    monkeypatch.setattr(cli.importlib_metadata, "version", lambda _: "1.2.3")

    exit_code = cli.main(["--version"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.strip() == "cloud-posture-watch 1.2.3"


def test_version_flag_fallback_when_metadata_unavailable(monkeypatch, capsys):
    def _raise(_):
        raise cli.importlib_metadata.PackageNotFoundError

    monkeypatch.setattr(cli.importlib_metadata, "version", _raise)

    exit_code = cli.main(["-V"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.strip() == "cloud-posture-watch (version metadata unavailable)"
