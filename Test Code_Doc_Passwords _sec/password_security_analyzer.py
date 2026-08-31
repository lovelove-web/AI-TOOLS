#!/usr/bin/env python3
"""
Password Security Analyzer module.

This module provides a comprehensive analysis of password strength,
including entropy calculation, common pattern detection, and
recommendations for improvement.
"""

import math
import re
import string
from typing import List, Dict, Any, Optional, Set


class PasswordSecurityAnalyzer:
    """Analyze password strength and provide security recommendations."""

    COMMON_PASSWORDS = {
        "password", "123456", "123456789", "qwerty", "abc123",
        "letmein", "welcome", "monkey", "dragon", "iloveyou",
        "admin", "football", "baseball", "shadow", "master",
        "superman", "trustno1", "sunshine", "princess", "batman",
    }

    KEYBOARD_SEQUENCES = [
        "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn",
        "1234567890", "0987654321", "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba", "1qaz", "2wsx", "3edc", "4rfv",
        "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/", "!qaz", "@wsx",
        "#edc", "$rfv", "%tgb", "^yhn", "&ujm", "*ik,", "(ol.", ")p;/"
    ]

    def __init__(self, custom_dictionary: Optional[Set[str]] = None) -> None:
        """
        Initialize the analyzer with an optional custom dictionary.

        :param custom_dictionary: An optional set of additional weak passwords
            or dictionary words to be used during analysis.
        """
        self.dictionary = set(self.COMMON_PASSWORDS)
        if custom_dictionary:
            self.dictionary.update(word.lower() for word in custom_dictionary)

    def analyze(self, password: Any) -> Dict[str, Any]:
        """
        Analyze a password and return a detailed security report.

        :param password: The password to analyze; must be a string.

        :return: A dictionary containing analysis results:
            - password: the original password
            - length: length of password
            - entropy: calculated Shannon entropy in bits
            - charset_size: estimated character pool size
            - strength: qualitative strength label
            - score: numeric security score (0-100)
            - issues: list of detected security issues
            - recommendations: list of suggested improvements
        :raises TypeError: if password is not a string.
        """
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")

        length = len(password)
        entropy = self.calculate_entropy(password)
        charset_size = self._get_charset_size(password)
        dict_words = self.detect_dictionary_words(password)
        patterns = self.detect_repeated_patterns(password)
        keyboard_seqs = self.detect_keyboard_sequences(password)

        issues = []
        if length == 0:
            issues.append("Password is empty.")
        elif length < 8:
            issues.append("Password is too short (less than 8 characters).")
        if dict_words:
            issues.append(f"Dictionary word detected: {', '.join(dict_words)}")
        if patterns:
            issues.append(f"Repeated pattern detected: {', '.join(patterns)}")
        if keyboard_seqs:
            issues.append(f"Keyboard sequence detected: {', '.join(keyboard_seqs)}")
        if length > 0 and not self._has_variety(password):
            issues.append("Password lacks character variety (use uppercase, lowercase, digits, symbols).")

        analysis = {
            "password": password,
            "length": length,
            "entropy": entropy,
            "charset_size": charset_size,
            "strength": self._classify_strength(entropy, length, len(issues)),
            "score": self.calculate_security_score(entropy, length, len(issues)),
            "issues": issues,
            "recommendations": self.generate_recommendations(issues, length, entropy),
            "dictionary_words": dict_words,
            "repeated_patterns": patterns,
            "keyboard_sequences": keyboard_seqs,
        }
        return analysis

    def calculate_entropy(self, password: str) -> float:
        """
        Calculate the Shannon entropy of a password.

        The entropy is computed as L * log2(R), where L is the password
        length and R is the estimated size of the character pool.

        :param password: The password string.
        :return: Entropy value in bits.
        """
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        if len(password) == 0:
            return 0.0
        pool_size = self._get_charset_size(password)
        if pool_size == 0:
            return 0.0
        return len(password) * math.log2(pool_size)

    def detect_dictionary_words(self, password: str) -> List[str]:
        """
        Detect common dictionary words within the password.

        Checks if the entire password or any substrings match known weak
        passwords or dictionary words from the internal set.

        :param password: The password string to examine.
        :return: List of detected dictionary words (lowercase).
        """
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        found = []
        lower_pw = password.lower()
        # Check whole password
        if lower_pw in self.dictionary:
            found.append(lower_pw)
        # Check substrings of length >= 4 that match dictionary words
        for word in self.dictionary:
            if len(word) >= 4 and word in lower_pw and word not in found:
                found.append(word)
        return found

    def detect_repeated_patterns(self, password: str) -> List[str]:
        """
        Detect repeated character patterns in a password.

        Finds consecutive repetitions of substrings (length 1 to 3) that
        appear at least twice, e.g., "abcabc", "111", "abab".

        :param password: The password string to analyze.
        :return: List of detected repeated pattern strings.
        """
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        patterns = []
        if len(password) < 2:
            return patterns
        max_pattern_len = min(3, len(password) // 2)
        for plen in range(1, max_pattern_len + 1):
            for i in range(0, len(password) - 2 * plen + 1):
                substr = password[i:i + plen]
                if substr == password[i + plen:i + 2 * plen]:
                    # Check if it repeats further
                    count = 1
                    j = i + plen
                    while j + plen <= len(password) and password[j:j + plen] == substr:
                        count += 1
                        j += plen
                    if count >= 2:
                        pattern_str = f"'{substr}' repeated {count} times"
                        if pattern_str not in patterns:
                            patterns.append(pattern_str)
        # Limit to avoid excessive output for very long strings
        return patterns[:20]

    def detect_keyboard_sequences(self, password: str) -> List[str]:
        """
        Detect keyboard sequences in a password.

        Checks for common keyboard layouts such as "qwerty", "asdf",
        and numeric sequences like "1234567890" in both directions.

        :param password: The password string to examine.
        :return: List of detected keyboard sequences.
        """
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        sequences = []
        lower_pw = password.lower()
        for seq in self.KEYBOARD_SEQUENCES:
            if seq in lower_pw:
                sequences.append(seq)
        # Detect simple ascending/descending character runs (length >= 4)
        ascii_runs = re.findall(
            r'(?:(?:a(?=b)|b(?=c)|c(?=d)|d(?=e)|e(?=f)|f(?=g)|g(?=h)|h(?=i)|i(?=j)|j(?=k)|k(?=l)|l(?=m)|m(?=n)|n(?=o)|o(?=p)|p(?=q)|q(?=r)|r(?=s)|s(?=t)|t(?=u)|u(?=v)|v(?=w)|w(?=x)|x(?=y)|y(?=z)|0(?=1)|1(?=2)|2(?=3)|3(?=4)|4(?=5)|5(?=6)|6(?=7)|7(?=8)|8(?=9))){3,}[a-z0-9]',
            lower_pw
        )
        for run in ascii_runs:
            if run not in sequences:
                sequences.append(run)
        return sequences[:20]

    def generate_recommendations(self, issues: List[str], length: int, entropy: float) -> List[str]:
        """
        Generate security recommendations based on detected issues.

        :param issues: List of detected issues.
        :param length: Password length.
        :param entropy: Password entropy in bits.
        :return: List of human-readable recommendations.
        """
        recommendations = []
        if not issues:
            recommendations.append("Password looks strong. No changes needed.")
            return recommendations

        if any("empty" in issue for issue in issues):
            recommendations.append("Create a non-empty password.")
        if any("too short" in issue for issue in issues):
            recommendations.append("Use at least 12-16 characters for better security.")
        if any("Dictionary word" in issue for issue in issues):
            recommendations.append("Avoid using common dictionary words or known weak passwords.")
        if any("Repeated pattern" in issue for issue in issues):
            recommendations.append("Avoid repeated character patterns (e.g., 'abcabc', '111').")
        if any("Keyboard sequence" in issue for issue in issues):
            recommendations.append("Avoid keyboard sequences like 'qwerty' or '123456'.")
        if any("variety" in issue for issue in issues):
            recommendations.append("Include a mix of uppercase, lowercase, digits, and special characters.")
        if entropy < 28:
            recommendations.append("Consider using a password manager to generate a high-entropy random password.")
        elif entropy < 60:
            recommendations.append("Increase password length or character variety to improve entropy.")
        return recommendations

    def calculate_security_score(self, entropy: float, length: int, issue_count: int) -> int:
        """
        Calculate a numeric security score from 0 to 100.

        The score starts at 100 and penalizes for low entropy, short length,
        and number of detected issues.

        :param entropy: Password entropy in bits.
        :param length: Password length.
        :param issue_count: Number of security issues detected.
        :return: Integer score between 0 and 100.
        """
        score = 100.0
        # Entropy penalty (0 to 50 points)
        if entropy < 28:
            score -= 50
        elif entropy < 40:
            score -= 35
        elif entropy < 60:
            score -= 20
        elif entropy < 80:
            score -= 10
        # Length penalty
        if length < 8:
            score -= 20
        elif length < 12:
            score -= 10
        # Issue penalty
        score -= min(issue_count * 5, 30)
        return max(0, min(100, int(score)))

    def _get_charset_size(self, password: str) -> int:
        """
        Estimate the character pool size based on character classes present.

        :param password: The password string.
        :return: Estimated pool size (integer).
        """
        if not password:
            return 0
        pool = 0
        if any(c.islower() for c in password):
            pool += 26
        if any(c.isupper() for c in password):
            pool += 26
        if any(c.isdigit() for c in password):
            pool += 10
        if any(c in string.punctuation for c in password):
            pool += 32
        # Account for non-ASCII Unicode characters (CJK, Arabic, emoji, etc.)
        if any(ord(c) > 127 for c in password):
            pool += 1000  # large conservative estimate for extended Unicode
        return pool

    def _has_variety(self, password: str) -> bool:
        """
        Check if password contains at least three character classes.

        :param password: The password string.
        :return: True if at least three of lowercase, uppercase, digits,
                 punctuation, or unicode are present.
        """
        classes = 0
        if any(c.islower() for c in password):
            classes += 1
        if any(c.isupper() for c in password):
            classes += 1
        if any(c.isdigit() for c in password):
            classes += 1
        if any(c in string.punctuation for c in password):
            classes += 1
        if any(ord(c) > 127 for c in password):
            classes += 1
        return classes >= 3

    def _classify_strength(self, entropy: float, length: int, issue_count: int) -> str:
        """
        Classify password strength based on entropy, length, and issues.

        :param entropy: Entropy in bits.
        :param length: Password length.
        :param issue_count: Number of issues detected.
        :return: Strength label as string.
        """
        if length == 0:
            return "Empty"
        if entropy < 28 or issue_count > 3:
            return "Very Weak"
        if entropy < 40 or issue_count > 2:
            return "Weak"
        if entropy < 60 or issue_count > 1:
            return "Moderate"
        if entropy < 80:
            return "Strong"
        return "Very Strong"