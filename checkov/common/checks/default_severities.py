"""
Default severity mappings for IaC checks when no API key is provided.
These severities are approximate and based on general security best practices.
For accurate and up-to-date severities, use a Bridgecrew/Prisma Cloud API key.
"""
from checkov.common.bridgecrew.severities import Severities, BcSeverities, Severity
from checkov.common.models.enums import CheckCategories


# Default severity mapping based on check categories
CATEGORY_TO_DEFAULT_SEVERITY: dict[CheckCategories, Severity] = {
    CheckCategories.SECRETS: Severities[BcSeverities.CRITICAL],
    CheckCategories.IAM: Severities[BcSeverities.HIGH],
    CheckCategories.ENCRYPTION: Severities[BcSeverities.HIGH],
    CheckCategories.NETWORKING: Severities[BcSeverities.MEDIUM],
    CheckCategories.GENERAL_SECURITY: Severities[BcSeverities.MEDIUM],
    CheckCategories.LOGGING: Severities[BcSeverities.LOW],
    CheckCategories.BACKUP_AND_RECOVERY: Severities[BcSeverities.MEDIUM],
    CheckCategories.CONVENTION: Severities[BcSeverities.LOW],
    CheckCategories.KUBERNETES: Severities[BcSeverities.MEDIUM],
    CheckCategories.APPLICATION_SECURITY: Severities[BcSeverities.HIGH],
    CheckCategories.SUPPLY_CHAIN: Severities[BcSeverities.HIGH],
    CheckCategories.API_SECURITY: Severities[BcSeverities.HIGH],
    CheckCategories.SAST: Severities[BcSeverities.HIGH],
    CheckCategories.AI_AND_ML: Severities[BcSeverities.MEDIUM],
}


def get_default_severity_for_check(check) -> Severity | None:
    """
    Get a default severity for a check based on its categories.
    Returns the highest severity if multiple categories exist.
    
    :param check: A check instance with a 'categories' attribute
    :return: A Severity object or None if no categories match
    """
    if not hasattr(check, 'categories') or not check.categories:
        return Severities[BcSeverities.MEDIUM]  # Default fallback
    
    highest_severity: Severity | None = None
    
    for category in check.categories:
        severity = CATEGORY_TO_DEFAULT_SEVERITY.get(category)
        if severity:
            if highest_severity is None or severity.level > highest_severity.level:
                highest_severity = severity
    
    return highest_severity or Severities[BcSeverities.MEDIUM]
