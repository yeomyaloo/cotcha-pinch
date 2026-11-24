package com.sherlockphones.android;

import org.xml.sax.Attributes;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 줄 번호가 붙은 작은 XML 트리. 매니페스트·네트워크 보안 설정을 읽는 데 쓴다.
 * 분석 대상 앱의 XML 은 믿을 수 없으므로 DOCTYPE 과 외부 엔티티를 모두 막는다 (XXE 방지).
 */
public final class XmlTree {

    /**
     * @param name  태그 이름 (접두사 포함, 예: activity)
     * @param attrs 속성 (접두사 포함, 예: android:exported)
     * @param line  시작 태그가 있는 줄 (속성이 여러 줄이면 첫 줄)
     */
    public record Element(String name, Map<String, String> attrs, int line, List<Element> children) {

        public Optional<String> attr(String name) {
            return Optional.ofNullable(attrs.get(name));
        }

        public List<Element> children(String name) {
            return children.stream().filter(c -> c.name().equals(name)).toList();
        }

        /** 자손 전체에서 이름이 같은 것 */
        public List<Element> descendants(String name) {
            List<Element> result = new ArrayList<>();
            for (Element child : children) {
                if (child.name().equals(name)) {
                    result.add(child);
                }
                result.addAll(child.descendants(name));
            }
            return result;
        }
    }

    /** 파싱한 파일. 속성이 적힌 줄을 찾을 수 있게 원문 줄도 가진다 */
    public record Document(Element root, List<String> lines) {

        /** 요소의 속성이 적힌 줄. 못 찾으면 요소의 줄 */
        public int lineOf(Element element, String attribute) {
            // 시작 태그가 끝나는 줄('>')까지 속성 이름을 찾는다
            for (int i = element.line(); i <= lines.size(); i++) {
                String text = lines.get(i - 1);
                if (text.contains(attribute + "=")) {
                    return i;
                }
                if (text.contains(">")) {
                    break;
                }
            }
            return element.line();
        }
    }

    private XmlTree() {
    }

    public static Document parse(Path file) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(false);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            SAXParser parser = factory.newSAXParser();
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            Handler handler = new Handler(lines);
            parser.parse(file.toFile(), handler);
            if (handler.root == null) {
                throw new IOException("빈 XML: " + file);
            }
            return new Document(handler.root, lines);
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("XML 을 읽지 못함: " + file.getFileName() + ": " + e.getMessage(), e);
        }
    }

    private static final class Handler extends DefaultHandler {

        private final List<String> lines;
        private final Deque<Element> stack = new ArrayDeque<>();
        private final Map<Element, StringBuilder> text = new java.util.IdentityHashMap<>();
        private Locator locator;
        private Element root;

        private Handler(List<String> lines) {
            this.lines = lines;
        }

        @Override
        public void setDocumentLocator(Locator locator) {
            this.locator = locator;
        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            Map<String, String> attrs = new LinkedHashMap<>();
            for (int i = 0; i < attributes.getLength(); i++) {
                attrs.put(attributes.getQName(i), attributes.getValue(i));
            }
            Element element = new Element(qName, attrs, startLine(qName), new ArrayList<>());
            if (stack.isEmpty()) {
                root = element;
            } else {
                stack.peek().children().add(element);
            }
            stack.push(element);
        }

        @Override
        public void characters(char[] ch, int start, int length) {
            if (!stack.isEmpty()) {
                text.computeIfAbsent(stack.peek(), e -> new StringBuilder()).append(ch, start, length);
            }
        }

        @Override
        public void endElement(String uri, String localName, String qName) {
            Element element = stack.pop();
            StringBuilder content = text.remove(element);
            // 글자는 속성 "#text" 로 둔다 (예: <domain>api.example.com</domain>)
            if (content != null && !content.toString().isBlank()) {
                element.attrs().put("#text", content.toString().strip());
            }
        }

        /** 로케이터는 시작 태그가 끝나는 줄을 준다. 위로 올라가며 '<태그' 가 있는 줄을 찾는다 */
        private int startLine(String qName) {
            int end = locator == null ? 1 : Math.max(1, locator.getLineNumber());
            for (int i = Math.min(end, lines.size()); i >= 1; i--) {
                String text = lines.get(i - 1);
                int at = text.indexOf("<" + qName);
                int next = at + qName.length() + 1;
                // <activity 는 찾고 <activity-alias 는 건너뛴다
                if (at >= 0 && (next == text.length() || Character.isWhitespace(text.charAt(next))
                        || text.charAt(next) == '>' || text.charAt(next) == '/')) {
                    return i;
                }
            }
            return end;
        }
    }
}
