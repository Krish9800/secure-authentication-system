"""Foundation test verifying secure_auth package layout."""

import secure_auth


def test_package_version() -> None:
    """Verify package version is defined."""
    assert secure_auth.__version__ == "0.1.0"
