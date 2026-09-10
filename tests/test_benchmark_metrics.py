"""
Phase 17 tests — validates the benchmark METRICS themselves against
known cases with a hand-computed expected answer. A benchmark harness
whose own math is untested would just be a number nobody can trust.
"""
from benchmarks.metrics import check_evidence_hallucination, precision_recall


class TestPrecisionRecall:
    def test_perfect_match_gives_precision_and_recall_of_one(self):
        result = precision_recall({"a", "b", "c"}, {"a", "b", "c"})
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.f1 == 1.0

    def test_false_positive_reduces_precision_not_recall(self):
        # predicted {a, b, c} but only {a, b} were actually expected —
        # c is a spurious extra prediction
        result = precision_recall({"a", "b", "c"}, {"a", "b"})
        assert result.true_positives == 2
        assert result.false_positives == 1
        assert result.false_negatives == 0
        assert result.precision == 2 / 3
        assert result.recall == 1.0

    def test_false_negative_reduces_recall_not_precision(self):
        # predicted {a} but {a, b} were expected — b was missed
        result = precision_recall({"a"}, {"a", "b"})
        assert result.true_positives == 1
        assert result.false_positives == 0
        assert result.false_negatives == 1
        assert result.precision == 1.0
        assert result.recall == 0.5

    def test_no_overlap_gives_zero_precision_and_recall(self):
        result = precision_recall({"x", "y"}, {"a", "b"})
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.f1 == 0.0

    def test_empty_predicted_and_empty_expected_is_a_perfect_score(self):
        """Predicting nothing when nothing exists to find is correct
        behavior, not a failure — should not be penalized."""
        result = precision_recall(set(), set())
        assert result.precision == 1.0
        assert result.recall == 1.0

    def test_f1_is_harmonic_mean_not_arithmetic_mean(self):
        # precision=1.0, recall=0.5 -> harmonic mean = 2*1*0.5/(1+0.5) = 0.667, not 0.75
        result = precision_recall({"a"}, {"a", "b"})
        assert abs(result.f1 - 0.6667) < 0.001


class TestHallucinationCheck:
    def test_all_claimed_values_present_in_source_gives_zero_rate(self):
        source = [{"public_ip": "203.0.113.42"}]
        ai_evidence = [{"field": "public_ip", "value": "203.0.113.42"}]
        result = check_evidence_hallucination(ai_evidence, source)
        assert result.hallucination_rate == 0.0
        assert result.unsupported_items == 0

    def test_fabricated_value_not_in_source_is_flagged(self):
        source = [{"public_ip": "203.0.113.42"}]
        ai_evidence = [{"field": "credentials", "value": "AKIAFAKEFAKEFAKE1234"}]
        result = check_evidence_hallucination(ai_evidence, source)
        assert result.unsupported_items == 1
        assert result.hallucination_rate == 1.0

    def test_mixed_grounded_and_fabricated_gives_partial_rate(self):
        source = [{"public_ip": "203.0.113.42"}]
        ai_evidence = [
            {"field": "public_ip", "value": "203.0.113.42"},  # grounded
            {"field": "made_up", "value": "totally-invented-value"},  # fabricated
        ]
        result = check_evidence_hallucination(ai_evidence, source)
        assert result.total_evidence_items == 2
        assert result.unsupported_items == 1
        assert result.hallucination_rate == 0.5

    def test_no_evidence_items_gives_zero_rate_not_division_error(self):
        result = check_evidence_hallucination([], [{"public_ip": "1.2.3.4"}])
        assert result.hallucination_rate == 0.0

    def test_empty_value_is_ignored_not_flagged(self):
        """An evidence item with an empty value string shouldn't count
        as a hallucination — there's nothing to check groundedness of."""
        result = check_evidence_hallucination([{"field": "note", "value": ""}], [])
        assert result.unsupported_items == 0
