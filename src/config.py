"""Loads config/scenario.yaml into typed settings used across the sandbox."""
from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "scenario.yaml"


class RoundsConfig(BaseModel):
    max_rounds: int = 20
    convergence_rounds_required: int = 3


class BudgetConfig(BaseModel):
    wcu_max_capacity: int = 250


class ThresholdsConfig(BaseModel):
    false_positive_rate_max: float = 0.01


class TrafficConfig(BaseModel):
    attacker_requests_per_round: int = 20
    legit_requests_per_round: int = 40
    rng_seed: int = 1337


class LLMConfig(BaseModel):
    backend: str = "ollama"
    ollama_model: str = "llama3.2"
    ollama_host: str = "http://localhost:11434"


class PersistenceConfig(BaseModel):
    db_path: str = "data/run.db"


class ScenarioConfig(BaseModel):
    rounds: RoundsConfig = RoundsConfig()
    budget: BudgetConfig = BudgetConfig()
    thresholds: ThresholdsConfig = ThresholdsConfig()
    traffic: TrafficConfig = TrafficConfig()
    llm: LLMConfig = LLMConfig()
    persistence: PersistenceConfig = PersistenceConfig()


def load_config(path: Path | str | None = None) -> ScenarioConfig:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    raw = yaml.safe_load(config_path.read_text())
    config = ScenarioConfig(**raw)
    # Lets docker-compose point at the `ollama` service name instead of
    # localhost without needing a separate config file.
    if os.environ.get("OLLAMA_HOST"):
        config.llm.ollama_host = os.environ["OLLAMA_HOST"]
    return config
