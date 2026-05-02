import pytest

from cloud_posture_watch_cli import _parse_provider_args, _run_collectors, main


def test_provider_filter_parses_repeatable_and_csv_and_scopes_execution():
    selected = _parse_provider_args(["aws,azure", "gcp"])
    assert selected == {"aws", "azure", "gcp"}

    selected = _parse_provider_args(["aws,gcp"])
    assert _run_collectors(selected) == ["aws", "gcp"]


def test_provider_filter_invalid_value_exits_with_error():
    with pytest.raises(SystemExit):
        main(["--provider", "aws,digitalocean"])
