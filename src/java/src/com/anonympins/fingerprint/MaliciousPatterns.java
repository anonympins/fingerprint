package com.anonympins.fingerprint;

import java.util.*;
import java.util.regex.Pattern;

public class MaliciousPatterns {
    private static final Map<String, Pattern> INJECTION_PATTERNS = new HashMap<>();

    static {
        INJECTION_PATTERNS.put("sql", Pattern.compile("(\\$ne|' *OR *'1'='1|['\";]\\s*--|; ?(DROP|TRUNCATE|DELETE)|UNION SELECT|(?:SLEEP|BENCHMARK)\\s*\\(|WAITFOR DELAY)", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("log4shell", Pattern.compile("\\$\\{jndi:(ldap|rmi|dns):", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("ssti", Pattern.compile("\\{\\{.*\\}\\}|\\{%.*%\\}"));
        INJECTION_PATTERNS.put("xxe", Pattern.compile("<!ENTITY\\s+.*SYSTEM", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("traversal", Pattern.compile("(\\.\\.\\/|\\.\\.)"));
        INJECTION_PATTERNS.put("rce", Pattern.compile("`.*`|(?:^|[\\n;&|]\\s*)(?:ping|ls|whoami|cat|rm|ncat|nc|bash|sh|powershell|cmd)\\b", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("ssrf", Pattern.compile("(?:https?://)?(?:127\\.\\d+\\.\\d+\\.\\d+|169\\.254\\.169\\.254|10\\.\\d+\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+|localhost|0\\.0\\.0\\.0|\\[[0:]+1\\])\\b", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("crlf", Pattern.compile("[\\r\\n]|%0[ad]", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("xss", Pattern.compile("(<script|javascript:|on\\w+\\s*=|alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\(|<img\\s+src[^>]+onerror|<iframe)", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("openRedirect", Pattern.compile("^(https?:)?//(?![^\\/]*?(localhost|127\\.0\\.0\\.1))[^\\s\\/]+", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("lfi", Pattern.compile("(?:etc/passwd|win\\.ini|boot\\.ini|php://filter|data://|zip://)", Pattern.CASE_INSENSITIVE));
        INJECTION_PATTERNS.put("shellshock", Pattern.compile("\\(\\)\\s*\\{\\s*:\\s*;\\s*\\}\\s*"));
        INJECTION_PATTERNS.put("nosql", Pattern.compile("\\$(?:eq|ne|gt|gte|lt|lte|in|nin|and|or|nor|not|expr|jsonSchema|mod|regex|text|where|elemMatch)", Pattern.CASE_INSENSITIVE));
    }

    public static boolean isMalicious(String str) {
        return isMalicious(str, null);
    }

    public static boolean isMalicious(String str, List<String> typesToDetect) {
        if (str == null) {
            return false;
        }
        Collection<String> types = typesToDetect;
        if (types == null) {
            List<String> allTypes = new ArrayList<>(INJECTION_PATTERNS.keySet());
            allTypes.remove("openRedirect");
            types = allTypes;
        }

        for (String type : types) {
            Pattern pattern = INJECTION_PATTERNS.get(type);
            if (pattern != null && pattern.matcher(str).find()) {
                return true;
            }
        }
        return false;
    }
}