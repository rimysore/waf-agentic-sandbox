import random

from src.corpus.legit_traffic import LEGIT_IP_POOL, generate_round_traffic, load_seed


def test_seed_has_a_reasonable_number_of_varied_entries():
    seed = load_seed()
    assert len(seed) >= 40
    paths = {entry["path"] for entry in seed}
    assert {"/login", "/search", "/comments"}.issubset(paths)


def test_generate_round_traffic_is_reproducible_with_same_seed():
    reqs_a = generate_round_traffic(20, random.Random(42))
    reqs_b = generate_round_traffic(20, random.Random(42))
    assert [r.model_dump() for r in reqs_a] == [r.model_dump() for r in reqs_b]


def test_generated_traffic_uses_legit_ip_pool_only():
    reqs = generate_round_traffic(30, random.Random(7))
    assert all(r.client_ip in LEGIT_IP_POOL for r in reqs)


def test_generated_traffic_disjoint_from_attacker_ip_range():
    reqs = generate_round_traffic(30, random.Random(7))
    assert all(not r.client_ip.startswith("203.0.113.") for r in reqs)
