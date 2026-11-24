package com.sherlockphones.findings;

import java.util.List;

/**
 * 취약점 발견. 조사 단계에서 record_finding 으로 OPEN 상태로 만들고, 검증 단계에서 submit_verdict 로 판정한다.
 *
 * @param entryPoint 외부 입력이 들어오는 진입점 (예: PROVIDER com.example.bank.data.StatementProvider)
 * @param sink       위험 지점 API (예: android.database.sqlite.SQLiteDatabase.rawQuery)
 * @param attacker   누가 공격하나: other_app(기기의 다른 앱), link(딥링크·웹 콘텐츠), network(같은 네트워크),
 *                   device(잃어버리거나 루팅된 폰, APK 를 받은 누구나). 모르면 null
 * @param commitSha  기록할 때 분석한 커밋 (모르면 null)
 */
public record Finding(String id, String title, String cwe, String severity, String confidence, String description,
                      String exploitScenario, List<Evidence> evidence, String entryPoint, String sink, String attacker,
                      Status status, Verification verification, String createdAt, String commitSha) {

    /** 공격자 종류 (위협 모델의 네 공격자) */
    public static final List<String> ATTACKERS = List.of("other_app", "link", "network", "device");

    /** 공격자 종류의 한국어 이름 */
    public static String attackerLabel(String attacker) {
        if (attacker == null) {
            return "-";
        }
        return switch (attacker) {
            case "other_app" -> "기기의 다른 앱";
            case "link" -> "조작된 링크·웹 콘텐츠";
            case "network" -> "같은 네트워크의 누군가";
            case "device" -> "잃어버리거나 루팅된 폰, APK 를 받은 누구나";
            default -> attacker;
        };
    }

    public enum Status {
        /** 검증 대기 */
        OPEN,
        /** 공격 가능함을 확인 */
        CONFIRMED,
        /** 오탐 */
        REJECTED,
        /** 판단 근거 부족 */
        UNCERTAIN
    }

    public record Evidence(String file, int line, String note) {
    }

    /** @param severity 검증 후 다시 매긴 심각도 (없으면 조사 단계 값을 쓴다) */
    public record Verification(String verdict, String reasoning, String blockingControls, String severity,
                               String verifiedAt) {
    }

    /** 검증 후 심각도가 있으면 그것을, 없으면 조사 단계 심각도 */
    public String effectiveSeverity() {
        return verification != null && verification.severity() != null ? verification.severity() : severity;
    }

    Finding withVerdict(Status status, Verification verification) {
        return new Finding(id, title, cwe, severity, confidence, description, exploitScenario, evidence, entryPoint, sink,
                attacker, status, verification, createdAt, commitSha);
    }
}
