from .base import Vulnerability
from .hardcoded_secrets import HardcodedPasswordsRule
from .weak_hash import WeakHashingCryptographyRule
from .command_injection import CommandInjectionRule
from .sql_injection import SqlInjectionRule
from .xss_risk import XssInsecureHttpResponseRule


# Export list of active rule instances
ALL_RULES = [
    HardcodedPasswordsRule(),
    WeakHashingCryptographyRule(),
    CommandInjectionRule(),
    SqlInjectionRule(),
    XssInsecureHttpResponseRule()
]
