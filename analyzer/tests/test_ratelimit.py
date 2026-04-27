"""Token-bucket limiter tests."""

from __future__ import annotations

import pytest

from analyzer.ratelimit import TokenBucketLimiter


def test_initial_burst_allowed(fake_clock):
    limiter = TokenBucketLimiter(rate_per_sec=10, burst=10, clock=fake_clock)
    for _ in range(10):
        assert limiter.allow("k") is True


def test_exhausted_bucket_rejects(fake_clock):
    limiter = TokenBucketLimiter(rate_per_sec=10, burst=5, clock=fake_clock)
    for _ in range(5):
        assert limiter.allow("k") is True
    assert limiter.allow("k") is False
    assert limiter.allow("k") is False


def test_bucket_refills_over_time(fake_clock):
    limiter = TokenBucketLimiter(rate_per_sec=10, burst=5, clock=fake_clock)
    for _ in range(5):
        limiter.allow("k")
    assert limiter.allow("k") is False
    fake_clock.advance(0.5)  # 0.5s * 10/s = 5 tokens
    assert limiter.allow("k") is True


def test_separate_keys_have_separate_buckets(fake_clock):
    limiter = TokenBucketLimiter(rate_per_sec=2, burst=2, clock=fake_clock)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    # different key still has full bucket
    assert limiter.allow("b") is True


def test_capacity_caps_refill(fake_clock):
    limiter = TokenBucketLimiter(rate_per_sec=1, burst=2, clock=fake_clock)
    # idle for a long time — bucket should not exceed capacity
    fake_clock.advance(3600)
    assert limiter.allow("k") is True
    assert limiter.allow("k") is True
    assert limiter.allow("k") is False  # only 2 tokens, not 3601


def test_zero_or_negative_rate_rejected():
    with pytest.raises(ValueError):
        TokenBucketLimiter(rate_per_sec=0)
    with pytest.raises(ValueError):
        TokenBucketLimiter(rate_per_sec=-1)


def test_zero_burst_rejected():
    with pytest.raises(ValueError):
        TokenBucketLimiter(rate_per_sec=1, burst=0)
