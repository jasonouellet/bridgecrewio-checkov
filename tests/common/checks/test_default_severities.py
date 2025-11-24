"""
Unit tests for default severity assignment
"""
import unittest
from checkov.common.checks.default_severities import (
    get_default_severity_for_check,
    CATEGORY_TO_DEFAULT_SEVERITY
)
from checkov.common.bridgecrew.severities import Severities, BcSeverities
from checkov.common.models.enums import CheckCategories


class MockCheck:
    """Mock check object for testing"""
    def __init__(self, categories):
        self.categories = categories


class TestDefaultSeverities(unittest.TestCase):
    
    def test_secrets_category_returns_critical(self):
        """Test that SECRETS category gets CRITICAL severity"""
        check = MockCheck([CheckCategories.SECRETS])
        severity = get_default_severity_for_check(check)
        self.assertEqual(severity, Severities[BcSeverities.CRITICAL])
    
    def test_iam_category_returns_high(self):
        """Test that IAM category gets HIGH severity"""
        check = MockCheck([CheckCategories.IAM])
        severity = get_default_severity_for_check(check)
        self.assertEqual(severity, Severities[BcSeverities.HIGH])
    
    def test_encryption_category_returns_high(self):
        """Test that ENCRYPTION category gets HIGH severity"""
        check = MockCheck([CheckCategories.ENCRYPTION])
        severity = get_default_severity_for_check(check)
        self.assertEqual(severity, Severities[BcSeverities.HIGH])
    
    def test_networking_category_returns_medium(self):
        """Test that NETWORKING category gets MEDIUM severity"""
        check = MockCheck([CheckCategories.NETWORKING])
        severity = get_default_severity_for_check(check)
        self.assertEqual(severity, Severities[BcSeverities.MEDIUM])
    
    def test_logging_category_returns_low(self):
        """Test that LOGGING category gets LOW severity"""
        check = MockCheck([CheckCategories.LOGGING])
        severity = get_default_severity_for_check(check)
        self.assertEqual(severity, Severities[BcSeverities.LOW])
    
    def test_multiple_categories_returns_highest_severity(self):
        """Test that multiple categories return the highest severity"""
        check = MockCheck([CheckCategories.LOGGING, CheckCategories.IAM, CheckCategories.CONVENTION])
        severity = get_default_severity_for_check(check)
        # Should return HIGH (from IAM) not LOW (from LOGGING/CONVENTION)
        self.assertEqual(severity, Severities[BcSeverities.HIGH])
    
    def test_no_categories_returns_default_medium(self):
        """Test that no categories returns default MEDIUM severity"""
        check = MockCheck([])
        severity = get_default_severity_for_check(check)
        self.assertEqual(severity, Severities[BcSeverities.MEDIUM])
    
    def test_all_categories_have_severity_mapping(self):
        """Test that all major categories have a severity mapping"""
        expected_categories = [
            CheckCategories.SECRETS,
            CheckCategories.IAM,
            CheckCategories.ENCRYPTION,
            CheckCategories.NETWORKING,
            CheckCategories.GENERAL_SECURITY,
        ]
        for category in expected_categories:
            self.assertIn(category, CATEGORY_TO_DEFAULT_SEVERITY)


if __name__ == '__main__':
    unittest.main()
