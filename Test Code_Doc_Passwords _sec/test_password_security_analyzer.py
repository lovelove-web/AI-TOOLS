#!/usr/bin/env python3
"""
Unit tests for PasswordSecurityAnalyzer.
"""

import unittest
import math
from password_security_analyzer import PasswordSecurityAnalyzer


class TestPasswordSecurityAnalyzer(unittest.TestCase):
    """Test suite for PasswordSecurityAnalyzer."""

    def setUp(self):
        """Set up a fresh analyzer instance for each test."""
        self.analyzer = PasswordSecurityAnalyzer()

    # ---------- Basic functionality tests ----------
    def test_analyze_valid_password(self):
        """Analyzing a strong password should return a report with no critical issues."""
        password = "Tr0ub4dor&3"
        report = self.analyzer.analyze(password)
        self.assertIsInstance(report, dict)
        self.assertEqual(report["password"], password)
        self.assertEqual(report["length"], len(password))
        self.assertGreater(report["entropy"], 40)
        self.assertGreaterEqual(report["score"], 60)
        self.assertIn("strength", report)
        self.assertIn("issues", report)
        self.assertIn("recommendations", report)

    def test_analyze_empty_password(self):
        """Empty password should yield zero entropy and a very weak rating."""
        report = self.analyzer.analyze("")
        self.assertEqual(report["length"], 0)
        self.assertEqual(report["entropy"], 0.0)
        self.assertEqual(report["strength"], "Empty")
        self.assertEqual(report["score"], 0)
        self.assertIn("Password is empty.", report["issues"])

    def test_analyze_non_string_raises_type_error(self):
        """Non-string inputs (int, float, None) must raise TypeError."""
        for value in [123, 3.14, None, [], {}]:
            with self.assertRaises(TypeError):
                self.analyzer.analyze(value)

    def test_calculate_entropy_empty(self):
        """Entropy of empty password is 0."""
        self.assertEqual(self.analyzer.calculate_entropy(""), 0.0)

    def test_calculate_entropy_known_value(self):
        """Entropy for 'a' should be log2(26)."""
        expected = math.log2(26)
        self.assertAlmostEqual(self.analyzer.calculate_entropy("a"), expected, places=5)

    def test_detect_dictionary_words(self):
        """Common dictionary words should be detected."""
        words = self.analyzer.detect_dictionary_words("mypassword123")
        self.assertIn("password", words)
        self.assertNotIn("letmein", words)

    def test_detect_repeated_patterns(self):
        """Repeated patterns like 'abcabc' and '111' should be detected."""
        patterns = self.analyzer.detect_repeated_patterns("abcabc111")
        self.assertTrue(any("abc" in p for p in patterns))
        self.assertTrue(any("1" in p for p in patterns))

    def test_detect_keyboard_sequences(self):
        """Keyboard sequences like 'qwerty' and '123456' should be detected."""
        seqs = self.analyzer.detect_keyboard_sequences("qwerty123456")
        self.assertIn("qwerty", seqs)
        self.assertIn("1234567890", seqs)  # full sequence contains 123456

    def test_generate_recommendations_empty_issues(self):
        """No issues leads to a positive recommendation."""
        recs = self.analyzer.generate_recommendations([], 16, 100)
        self.assertIn("Password looks strong. No changes needed.", recs)

    def test_generate_recommendations_short_password(self):
        """Short password should trigger length recommendation."""
        recs = self.analyzer.generate_recommendations(["Password is too short (less than 8 characters)."], 4, 10)
        self.assertTrue(any("12-16" in r for r in recs))

    def test_calculate_security_score_clamps(self):
        """Score must always be between 0 and 100."""
        self.assertEqual(self.analyzer.calculate_security_score(-10, 0, 10), 0)
        self.assertEqual(self.analyzer.calculate_security_score(200, 30, 0), 100)
        self.assertGreaterEqual(self.analyzer.calculate_security_score(50, 10, 2), 0)
        self.assertLessEqual(self.analyzer.calculate_security_score(50, 10, 2), 100)

    def test_charset_size_basic(self):
        """Charset size for lowercase only should be 26."""
        self.assertEqual(self.analyzer._get_charset_size("abc"), 26)

    def test_charset_size_mixed(self):
        """Charset size for mixed classes should include all relevant pools."""
        self.assertEqual(self.analyzer._get_charset_size("aA1!"), 26 + 26 + 10 + 32)

    # ---------- Unusual input tests ----------
    def test_analyze_chinese_characters(self):
        """Chinese characters should be accepted and analyzed normally."""
        password = "密码安全测试"
        report = self.analyzer.analyze(password)
        self.assertEqual(report["length"], len(password))
        self.assertGreater(report["entropy"], 0)
        self.assertIsInstance(report["score"], int)

    def test_analyze_arabic_characters(self):
        """Arabic characters should be accepted and analyzed normally."""
        password = "كلمةالسر"
        report = self.analyzer.analyze(password)
        self.assertEqual(report["length"], len(password))
        self.assertGreater(report["entropy"], 0)
        self.assertIsInstance(report["score"], int)

    def test_analyze_emoji(self):
        """Emoji should be accepted and analyzed normally."""
        password = "😀😁😂"
        report = self.analyzer.analyze(password)
        self.assertEqual(report["length"], len(password))
        self.assertGreater(report["entropy"], 0)
        self.assertIsInstance(report["score"], int)

    def test_analyze_long_string(self):
        """Very long strings (10000+ characters) should not crash and should be analyzed."""
        password = "a" * 10000
        report = self.analyzer.analyze(password)
        self.assertEqual(report["length"], 10000)
        self.assertGreater(report["entropy"], 0)
        self.assertTrue(any("Repeated pattern" in issue for issue in report["issues"]))
        self.assertLessEqual(report["score"], 100)

    def test_analyze_special_unicode_symbols(self):
        """Special Unicode symbols should be accepted and analyzed normally."""
        password = "§±∞¶•ªº"
        report = self.analyzer.analyze(password)
        self.assertEqual(report["length"], len(password))
        self.assertGreater(report["entropy"], 0)
        self.assertIsInstance(report["score"], int)

    def test_analyze_infinity_raises_type_error(self):
        """float('inf') is not a string and must raise TypeError."""
        with self.assertRaises(TypeError):
            self.analyzer.analyze(float('inf'))

    def test_analyze_negative_infinity_raises_type_error(self):
        """float('-inf') is not a string and must raise TypeError."""
        with self.assertRaises(TypeError):
            self.analyzer.analyze(float('-inf'))

    def test_analyze_nan_raises_type_error(self):
        """float('nan') is not a string and must raise TypeError."""
        with self.assertRaises(TypeError):
            self.analyzer.analyze(float('nan'))

    def test_analyze_none_raises_type_error(self):
        """None is not a string and must raise TypeError."""
        with self.assertRaises(TypeError):
            self.analyzer.analyze(None)


if __name__ == "__main__":
    unittest.main()