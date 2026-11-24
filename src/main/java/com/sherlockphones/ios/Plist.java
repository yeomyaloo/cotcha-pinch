package com.sherlockphones.ios;

import com.sherlockphones.android.XmlTree.Document;
import com.sherlockphones.android.XmlTree.Element;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * XML plist (Info.plist, *.entitlements) 하나. &lt;dict&gt; 는 &lt;key&gt; 와 값이 번갈아 나온다.
 *
 * @param path 앱 폴더 기준 경로
 */
public record Plist(String path, Document document) {

    /** dict 의 한 항목. 줄 번호는 key 의 줄을 쓴다 */
    public record Entry(String key, Element keyElement, Element value) {

        public int line() {
            return keyElement.line();
        }

        public boolean isTrue() {
            return value != null && value.name().equals("true");
        }

        public String text() {
            return value == null ? "" : value.attrs().getOrDefault("#text", "");
        }
    }

    /** 맨 위 dict */
    public Map<String, Entry> root() {
        Element top = document.root().children("dict").stream().findFirst().orElse(null);
        return top == null ? Map.of() : dict(top);
    }

    public static Map<String, Entry> dict(Element dict) {
        Map<String, Entry> result = new LinkedHashMap<>();
        List<Element> children = dict.children();
        for (int i = 0; i + 1 < children.size(); i++) {
            Element key = children.get(i);
            if (key.name().equals("key")) {
                String name = key.attrs().getOrDefault("#text", "");
                result.put(name, new Entry(name, key, children.get(i + 1)));
                i++;
            }
        }
        return result;
    }

    public static Optional<Map<String, Entry>> dictValue(Entry entry) {
        return entry != null && entry.value() != null && entry.value().name().equals("dict")
                ? Optional.of(dict(entry.value())) : Optional.empty();
    }

    /** array 안의 값들 */
    public static List<Element> items(Entry entry) {
        return entry != null && entry.value() != null && entry.value().name().equals("array")
                ? entry.value().children() : List.of();
    }

    /** array 안의 문자열 */
    public static List<String> strings(Entry entry) {
        List<String> result = new ArrayList<>();
        for (Element item : items(entry)) {
            if (item.name().equals("string")) {
                result.add(item.attrs().getOrDefault("#text", ""));
            }
        }
        return result;
    }
}
