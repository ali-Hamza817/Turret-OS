"""turret_graph CLI — load Parquet records into Neo4j KG."""

from __future__ import annotations

import logging

import click

from turret_common.config import get_settings
from turret_graph.loader import Neo4jLoader
from pathlib import Path


@click.group()
def cli() -> None:
    """TURRET OS L2 Graph commands."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


@cli.command()
@click.option("--parquet", default="data/processed/records.parquet",
              type=click.Path(exists=True), help="Parquet file to load.")
@click.option("--config", default="config/default.yaml", type=click.Path(exists=True))
@click.option("--apply-schema/--no-apply-schema", default=True)
def load(parquet: str, config: str, apply_schema: bool) -> None:
    """Load Parquet records into the Neo4j provenance KG."""
    settings = get_settings()
    with Neo4jLoader(
        uri=settings.neo4j_uri,
        user=settings.neo4j_user,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    ) as loader:
        if apply_schema:
            schema_path = Path(__file__).parent / "schema.cypher"
            loader.apply_schema(schema_path)
        total = loader.load_parquet(Path(parquet))
        click.echo(f"✅  Loaded {total:,} records into Neo4j")


if __name__ == "__main__":
    cli()
