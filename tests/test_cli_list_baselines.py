import cloud_posture_watch_cli as cli


def test_list_baselines_success_and_error(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_discover_baseline_profiles",
        lambda _p: {"aws": ["minimal", "standard"], "gcp": ["strict"]},
    )
    rc = cli.main(["--list-baselines"])
    out = capsys.readouterr()
    assert rc == 0
    assert out.err == ""
    assert out.out.splitlines() == ["aws/minimal", "aws/standard", "gcp/strict"]

    monkeypatch.setattr(
        cli,
        "_discover_baseline_profiles",
        lambda _p: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    rc = cli.main(["--list-baselines"])
    out = capsys.readouterr()
    assert rc != 0
    assert "boom" in out.err
