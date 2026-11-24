package com.sherlockphones.codegraph;

import java.util.List;
import java.util.Map;

/**
 * 앱 밖에서 들어올 수 있는 입구. 안드로이드는 외부에 열린 Activity·Service·Receiver·Provider 다.
 * 코드 그래프에서 진입점(ENTRY_POINT)이 되고, 클래스의 handlerMethods 로 이어진다.
 *
 * @param kind           ACTIVITY, SERVICE, RECEIVER, PROVIDER 등
 * @param className      구현 클래스 이름 (FQN)
 * @param handlerMethods 밖에서 들어온 입력을 받는 메서드 이름 (onCreate, onReceive, query 등)
 * @param declaredIn     선언한 파일 (예: app/src/main/AndroidManifest.xml)
 * @param line           선언한 줄
 * @param props          exported, permission, actions, deepLinks 등 표시용 정보
 */
public record Component(String kind, String className, List<String> handlerMethods, String declaredIn, int line,
                        Map<String, Object> props) {

    /** 진입점 이름 (예: ACTIVITY com.example.bank.web.WebActivity) */
    public String label() {
        return kind + " " + className;
    }
}
