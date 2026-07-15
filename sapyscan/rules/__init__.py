from .base import Vulnerability
from .hardcoded_secrets import HardcodedPasswordsRule
from .weak_hash import WeakHashingCryptographyRule
from .command_injection import CommandInjectionRule
from .sql_injection import SqlInjectionRule
from .xss_risk import XssInsecureHttpResponseRule
from .insecure_deserialization import InsecureDeserializationRule
from .path_traversal import PathTraversalRule
from .insecure_ssl import InsecureSslTlsRule
from .dangerous_eval import DangerousEvalExecRule
from .flask_debug import FlaskDebugModeRule
from .ssrf import SsrfRequestRule
from .assert_check import AssertSecurityCheckRule
from .weak_cipher import WeakCipherRule
from .weak_random import WeakRandomGeneratorRule
from .xxe_risk import XxeRiskRule
from .redos_risk import RedosRiskRule
from .jwt_security import JwtSecurityRule


# Export list of active rule instances
ALL_RULES = [
    HardcodedPasswordsRule(),
    WeakHashingCryptographyRule(),
    CommandInjectionRule(),
    SqlInjectionRule(),
    XssInsecureHttpResponseRule(),
    InsecureDeserializationRule(),
    PathTraversalRule(),
    InsecureSslTlsRule(),
    DangerousEvalExecRule(),
    FlaskDebugModeRule(),
    SsrfRequestRule(),
    AssertSecurityCheckRule(),
    WeakCipherRule(),
    WeakRandomGeneratorRule(),
    XxeRiskRule(),
    RedosRiskRule(),
    JwtSecurityRule()
]
