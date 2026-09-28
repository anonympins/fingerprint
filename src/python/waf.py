import re
from typing import List, Optional


class MaliciousPatterns:
    """Provides utilities for recursive WAF detection on inputs."""
    INJECTION_PATTERNS = {
        "sql": re.compile(r"(\$ne|' *OR *'1'='1|['\";]\s*--|; ?(DROP|TRUNCATE|DELETE)|UNION SELECT|(?:SLEEP|BENCHMARK)\s*\(|WAITFOR DELAY)", re.IGNORECASE),
        "log4shell": re.compile(r"\$\{jndi:(ldap|rmi|dns):", re.IGNORECASE),
        "ssti": re.compile(r"\{\{.*\}\}|\{%.*%\}"),
        "xxe": re.compile(r"<!ENTITY\s+.*SYSTEM", re.IGNORECASE),
        "traversal": re.compile(r"(\.\.\/|\.\.)"),
        "rce": re.compile(r"`.*`|(?:^|[\n;&|]\s*)(?:ping|ls|whoami|cat|rm|ncat|nc|bash|sh|powershell|cmd)\b", re.IGNORECASE),
        "ssrf": re.compile(r"(?:https?://)?(?:127\.\d+\.\d+\.\d+|169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|0\.0\.0\.0|\[[0:]+1\])\b", re.IGNORECASE),
        "crlf": re.compile(r"[\r\n]|%0[ad]", re.IGNORECASE),
        "xss": re.compile(r"(<script|javascript:|on\w+\s*=|alert\s*\(|confirm\s*\(|prompt\s*\(|<img\s+src[^>]+onerror|<iframe)", re.IGNORECASE),
        "openRedirect": re.compile(r"^(https?:)?//(?![^\/]*?(localhost|127\.0.0\.1))[^\s\/]+", re.IGNORECASE),
        "lfi": re.compile(r"(?:etc/passwd|win\.ini|boot\.ini|php://filter|data://|zip://)", re.IGNORECASE),
        "shellshock": re.compile(r"\(\)\s*\{\s*:\s*;\s*\}\s*", re.IGNORECASE),
        "nosql": re.compile(r"\$(?:eq|ne|gt|gte|lt|lte|in|nin|and|or|nor|not|expr|jsonSchema|mod|regex|text|where|elemMatch)", re.IGNORECASE)
    }

    @staticmethod
    def is_malicious(string: str, types_to_detect: Optional[List[str]] = None) -> bool:
        if not string or not isinstance(string, str):
            return False
        if not types_to_detect:
            types_to_detect = [k for k in MaliciousPatterns.INJECTION_PATTERNS.keys() if k != "openRedirect"]
        for t in types_to_detect:
            pattern = MaliciousPatterns.INJECTION_PATTERNS.get(t)
            if pattern and pattern.search(string):
                return True
        return False