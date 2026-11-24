package com.sherlockphones.findings;

import java.util.HashMap;
import java.util.Map;

/**
 * CWE → OWASP Mobile Top 10 (2024) 과 MASVS 분류. 보고서에 같이 적는다.
 */
public final class MobileMapping {

    /** @param top10 예: M4 · Insufficient Input/Output Validation */
    public record Mapping(String top10, String masvs) {
    }

    private static final Mapping UNKNOWN = new Mapping("-", "-");

    private static final Map<String, String> TOP10_NAMES = Map.of(
            "M1", "Improper Credential Usage",
            "M2", "Inadequate Supply Chain Security",
            "M3", "Insecure Authentication/Authorization",
            "M4", "Insufficient Input/Output Validation",
            "M5", "Insecure Communication",
            "M6", "Inadequate Privacy Controls",
            "M7", "Insufficient Binary Protections",
            "M8", "Security Misconfiguration",
            "M9", "Insecure Data Storage",
            "M10", "Insufficient Cryptography");

    private static final Map<String, String[]> BY_CWE = new HashMap<>();

    static {
        put("M4", "MASVS-CODE", "CWE-89", "CWE-78", "CWE-77", "CWE-94", "CWE-22", "CWE-23", "CWE-502", "CWE-611", "CWE-20");
        put("M4", "MASVS-PLATFORM", "CWE-79", "CWE-749", "CWE-601", "CWE-939");
        put("M5", "MASVS-NETWORK", "CWE-295", "CWE-297", "CWE-319", "CWE-311");
        put("M8", "MASVS-PLATFORM", "CWE-926", "CWE-927", "CWE-940", "CWE-925", "CWE-1021");
        put("M8", "MASVS-RESILIENCE", "CWE-489");
        put("M9", "MASVS-STORAGE", "CWE-312", "CWE-922", "CWE-532", "CWE-530", "CWE-732", "CWE-200", "CWE-359");
        put("M10", "MASVS-CRYPTO", "CWE-327", "CWE-328", "CWE-326", "CWE-321", "CWE-330", "CWE-338");
        put("M1", "MASVS-CRYPTO", "CWE-798", "CWE-259");
        put("M3", "MASVS-AUTH", "CWE-287", "CWE-306", "CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-347");
        put("M2", "MASVS-CODE", "CWE-1104", "CWE-1395");
    }

    private MobileMapping() {
    }

    public static Mapping of(String cwe) {
        if (cwe == null) {
            return UNKNOWN;
        }
        String[] found = BY_CWE.get(cwe.toUpperCase());
        return found == null ? UNKNOWN : new Mapping(found[0] + " · " + TOP10_NAMES.get(found[0]), found[1]);
    }

    /** 짧은 표기 (예: M4 / MASVS-CODE) */
    public static String brief(String cwe) {
        String[] found = cwe == null ? null : BY_CWE.get(cwe.toUpperCase());
        return found == null ? "-" : found[0] + " / " + found[1];
    }

    private static void put(String top10, String masvs, String... cwes) {
        for (String cwe : cwes) {
            BY_CWE.put(cwe, new String[]{top10, masvs});
        }
    }
}
