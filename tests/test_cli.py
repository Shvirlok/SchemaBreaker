"""CLI Integration Tests."""

from click.testing import CliRunner
from schemabreaker.cli import main


def test_cli_list_demos():
    runner = CliRunner()
    result = runner.invoke(main, ["list-demos"])
    assert result.exit_code == 0
    assert "ecommerce" in result.output
    assert "clinical" in result.output
    assert "financial" in result.output


def test_cli_demo_mock_run():
    runner = CliRunner()
    result = runner.invoke(main, ["demo", "--schema", "ecommerce", "-n", "5"])
    assert result.exit_code == 0
    assert "CustomerOrder" in result.output
    assert "SCHEMA HEALTH SCORE" in result.output
    assert "Attack Vector Resilience Breakdown" in result.output


def test_cli_run_custom_vectors():
    runner = CliRunner()
    result = runner.invoke(main, [
        "run",
        "-s", "clinical",
        "-n", "6",
        "--mock",
        "-v", "boundary_stress",
        "-v", "unicode_stress"
    ])
    assert result.exit_code == 0
    assert "ClinicalAssessment" in result.output
    assert "Pass Rate" in result.output
