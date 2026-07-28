"""
turret_harvest.cli
==================
CLI entry-point for the L1 Harvest layer.
Usage: python -m turret_harvest.cli --source /path/to/data --out output.parquet
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from turret_harvest.orchestrator import HarvestOrchestrator
from turret_harvest.sink import ParquetSink

console = Console()
logger = logging.getLogger(__name__)


@click.command()
@click.option(
    "--source", "-s",
    required=True,
    type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    help="Source directory to harvest metadata from.",
)
@click.option(
    "--out", "-o",
    default="data/processed/records.parquet",
    show_default=True,
    help="Output Parquet file path.",
)
@click.option(
    "--config", "-c",
    default="config/default.yaml",
    show_default=True,
    type=click.Path(exists=True),
    help="YAML config file path.",
)
@click.option(
    "--classifier",
    default="open",
    type=click.Choice(["open", "cui", "secret", "ts", "ts_sci"]),
    show_default=True,
    help="Default security classifier for all harvested files.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable DEBUG logging.")
def main(source: str, out: str, config: str, classifier: str, verbose: bool) -> None:
    """TURRET OS L1 Harvest — extract metadata from all supported file formats."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    source_path = Path(source)
    out_path = Path(out)
    config_data: dict[str, Any] = {}

    with open(config) as f:
        config_data = yaml.safe_load(f)

    console.rule("[bold cyan]TURRET OS — L1 Harvest")
    console.print(f"  Source : [yellow]{source_path}[/]")
    console.print(f"  Output : [yellow]{out_path}[/]")
    console.print(f"  Classif: [yellow]{classifier}[/]")

    orchestrator = HarvestOrchestrator(source_path, config_data)
    sink = ParquetSink(out_path)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Harvesting...", total=None)
        count = orchestrator.harvest(sink, classifier=classifier)
        progress.update(task, description=f"Harvested {count} records", completed=count)

    written = sink.flush()
    console.print(f"\n✅  [bold green]Done.[/] {count} records → [cyan]{written}[/]")


if __name__ == "__main__":
    main()
