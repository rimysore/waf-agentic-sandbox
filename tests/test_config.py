import os

from src.config import load_config


def test_default_config_loads_with_expected_shape():
    config = load_config()
    assert config.llm.backend == "ollama"
    assert config.rounds.max_rounds > 0


def test_ollama_host_env_var_overrides_config(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama:11434")
    config = load_config()
    assert config.llm.ollama_host == "http://ollama:11434"


def test_no_env_var_keeps_config_default(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    config = load_config()
    assert config.llm.ollama_host == "http://localhost:11434"
