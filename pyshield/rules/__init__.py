from .base import Vulnerability
from .hardcoded_secrets import HardcodedPasswordsRule
from .weak_hash import WeakHashingCryptographyRule
from .command_injection import CommandInjectionRule
from .sql_injection import SqlInjectionRule
from .xss_risk import XssInsecureHttpResponseRule
from .insecure_deserialization import InsecureDeserializationRule
from .path_traversal import PathTraversalRule
from .insecure_ssl import InsecureSslTlsRule


# Export list of active rule instances
ALL_RULES = [
    HardcodedPasswordsRule(),
    WeakHashingCryptographyRule(),
    CommandInjectionRule(),
    SqlInjectionRule(),
    XssInsecureHttpResponseRule(),
    InsecureDeserializationRule(),
    PathTraversalRule(),
    InsecureSslTlsRule()
]
