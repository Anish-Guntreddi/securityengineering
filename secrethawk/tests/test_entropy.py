"""Tests for entropy math and high-entropy detection."""

import math

import pytest

from secrethawk.entropy import (
    extract_candidate_tokens,
    is_high_entropy,
    shannon_entropy,
)


def test_entropy_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_single_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_uniform_two_symbols():
    # "abab" -> two symbols equally likely -> 1 bit/char.
    assert shannon_entropy("abab") == pytest.approx(1.0)


def test_entropy_uniform_four_symbols():
    # Four equally-likely symbols -> 2 bits/char.
    assert shannon_entropy("abcdabcd") == pytest.approx(2.0)


def test_entropy_matches_manual_formula():
    s = "aabb cc"
    # Compute manually.
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    expected = -sum(
        (c / len(s)) * math.log2(c / len(s)) for c in counts.values()
    )
    assert shannon_entropy(s) == pytest.approx(expected)


def test_high_entropy_true_for_random_token():
    token = "g7Xq2Lp9Zk4Rb8Wm3Vn6Td1Yc5Hj0Fs7Ae2Qo"
    assert is_high_entropy(token) is True


def test_high_entropy_false_for_short():
    assert is_high_entropy("aB3xZ") is False  # too short


def test_high_entropy_false_for_low_entropy_even_if_long():
    assert is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaa") is False


def test_high_entropy_false_for_sha256():
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert is_high_entropy(digest) is False


def test_high_entropy_false_for_uuid():
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert is_high_entropy(uuid) is False


def test_high_entropy_none_token():
    assert is_high_entropy(None) is False


def test_extract_candidate_tokens_quoted():
    line = 'api_key = "g7Xq2Lp9Zk4Rb8Wm3Vn6Td"'
    tokens = list(extract_candidate_tokens(line))
    assert "g7Xq2Lp9Zk4Rb8Wm3Vn6Td" in tokens


def test_extract_candidate_tokens_assignment_bare():
    line = "TOKEN=g7Xq2Lp9Zk4Rb8Wm3Vn6Td1Yc5Hj0Fs7Ae2Qo"
    tokens = list(extract_candidate_tokens(line))
    assert "g7Xq2Lp9Zk4Rb8Wm3Vn6Td1Yc5Hj0Fs7Ae2Qo" in tokens


def test_extract_candidate_tokens_dedup():
    line = 'x = "abc" ; y = "abc"'
    tokens = list(extract_candidate_tokens(line))
    assert tokens.count("abc") == 1
