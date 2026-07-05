from src.wafsim.rate_limit import SlidingWindowRateLimiter


def test_limit_not_exceeded_under_threshold():
    clock = {"t": 0.0}
    limiter = SlidingWindowRateLimiter(clock=lambda: clock["t"])
    for i in range(3):
        clock["t"] = float(i)
        exceeded = limiter.record_and_check("rule-a", "1.2.3.4", limit=5, window_sec=60)
    assert exceeded is False


def test_limit_exceeded_once_over_threshold():
    clock = {"t": 0.0}
    limiter = SlidingWindowRateLimiter(clock=lambda: clock["t"])
    exceeded = False
    for i in range(6):
        clock["t"] = float(i)
        exceeded = limiter.record_and_check("rule-a", "1.2.3.4", limit=5, window_sec=60)
    assert exceeded is True


def test_independent_keys_tracked_separately():
    clock = {"t": 0.0}
    limiter = SlidingWindowRateLimiter(clock=lambda: clock["t"])
    for _ in range(5):
        limiter.record_and_check("rule-a", "1.1.1.1", limit=3, window_sec=60)
    exceeded_other_ip = limiter.record_and_check("rule-a", "2.2.2.2", limit=3, window_sec=60)
    assert exceeded_other_ip is False


def test_window_slides_out_old_hits():
    clock = {"t": 0.0}
    limiter = SlidingWindowRateLimiter(clock=lambda: clock["t"])
    for t in (0.0, 1.0, 2.0):
        clock["t"] = t
        limiter.record_and_check("rule-a", "1.2.3.4", limit=2, window_sec=5)
    clock["t"] = 10.0
    exceeded = limiter.record_and_check("rule-a", "1.2.3.4", limit=2, window_sec=5)
    assert exceeded is False
    assert limiter.current_count("rule-a", "1.2.3.4", window_sec=5) == 1
