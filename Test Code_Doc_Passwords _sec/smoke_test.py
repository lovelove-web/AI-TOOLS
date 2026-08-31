#!/usr/bin/env python3
"""
Smoke tests for PasswordSecurityAnalyzer.

These tests perform basic sanity checks to ensure the application starts
and runs without fatal errors.
"""

from password_security_analyzer import PasswordSecurityAnalyzer


def run_smoke_tests():
    """Run a series of smoke tests and print results."""
    analyzer = PasswordSecurityAnalyzer()
    test_passwords = [
        "password",
        "Tr0ub4dor&3",
        "correct horse battery staple",
        "密码安全测试",
        "😀😁😂",
        "a" * 100,
    ]

    print("Running smoke tests...")
    for pwd in test_passwords:
        try:
            report = analyzer.analyze(pwd)
            print(f"Password: {pwd[:10]}... (len {report['length']})")
            print(f"  Entropy: {report['entropy']:.2f} bits")
            print(f"  Strength: {report['strength']}")
            print(f"  Score: {report['score']}")
            print(f"  Issues: {report['issues']}")
            print(f"  Recommendations: {report['recommendations']}")
            print("-" * 50)
        except Exception as exc:
            print(f"ERROR analyzing {pwd}: {exc}")
            return False
    print("Smoke tests passed.")
    return True


if __name__ == "__main__":
    success = run_smoke_tests()
    exit(0 if success else 1)