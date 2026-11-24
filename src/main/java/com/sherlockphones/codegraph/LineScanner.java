package com.sherlockphones.codegraph;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 줄 단위 규칙으로 앱 소스에서 위험 지점 후보를 찾는다. 플랫폼마다 규칙 목록만 다르게 넘긴다.
 * 테스트 코드, 빌드 결과물, 주석, 압축된 긴 줄은 건너뛰고, 한 줄에서는 처음 맞은 규칙 하나만 쓴다.
 */
public final class LineScanner {

    private static final Set<String> SKIP_DIRS = Set.of(".git", ".gradle", ".idea", "build", "out", "target", "node_modules",
            "Pods", "Carthage", "DerivedData", ".build", "generated", "intermediates");
    /** src/test, src/androidTest 처럼 테스트 소스 폴더 */
    private static final Set<String> TEST_DIRS = Set.of("test", "androidTest", "testDebug", "testRelease", "Tests", "UITests");
    private static final int MAX_DEPTH = 20;
    private static final long MAX_FILE_BYTES = 1_000_000;
    private static final int MAX_LINE_LENGTH = 1_000;
    private static final int MAX_SINKS = 3_000;
    private static final int SNIPPET_MAX_LENGTH = 160;

    private LineScanner() {
    }

    public static List<StaticSink> scan(Path root, List<LineRule> rules) {
        Set<String> extensions = rules.stream().flatMap(r -> r.extensions().stream()).collect(Collectors.toSet());
        List<StaticSink> sinks = new ArrayList<>();
        for (Path file : files(root, extensions)) {
            String relative = root.relativize(file).toString().replace('\\', '/');
            String extension = extension(file.getFileName().toString());
            List<LineRule> applicable = rules.stream().filter(r -> r.appliesTo(extension)).toList();
            List<String> lines;
            try {
                lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            } catch (IOException | UncheckedIOException e) {
                continue;
            }
            boolean inBlockComment = false;
            for (int i = 0; i < lines.size() && sinks.size() < MAX_SINKS; i++) {
                String line = lines.get(i);
                String trimmed = line.strip();
                if (inBlockComment) {
                    inBlockComment = !trimmed.contains("*/") && !trimmed.contains("-->");
                    continue;
                }
                if ((trimmed.startsWith("/*") && !trimmed.contains("*/")) || (trimmed.startsWith("<!--") && !trimmed.contains("-->"))) {
                    inBlockComment = true;
                    continue;
                }
                if (line.length() > MAX_LINE_LENGTH || isComment(trimmed)) {
                    continue;
                }
                for (LineRule rule : applicable) {
                    Matcher m = rule.pattern().matcher(line);
                    if (m.find()) {
                        sinks.add(new StaticSink(relative, i + 1, m.start() + 1, rule.category(), rule.cwe(), rule.api(),
                                safeSnippet(line, rule, m), StaticSink.LINE));
                        break;
                    }
                }
            }
        }
        return sinks;
    }

    /** 규칙이 찾은 값이 비밀값이면 그 값을, 아니어도 줄에 섞인 비밀값을 가린다 */
    private static String safeSnippet(String line, LineRule rule, Matcher m) {
        String text = snippet(line, rule.secret() ? m : null);
        return SecretMasker.mayHoldSecretLiteral(rule.cwe()) ? SecretMasker.maskLiterals(text) : SecretMasker.mask(text);
    }

    /** 코드 한 줄. 비밀값이면 찾은 값의 앞 4글자만 남기고 가린다 */
    public static String snippet(String line, Matcher secret) {
        String text = line;
        if (secret != null) {
            String found = secret.group();
            String masked = found.length() <= 4 ? "****" : found.substring(0, 4) + "****(가림)";
            text = line.substring(0, secret.start()) + masked + line.substring(secret.end());
        }
        text = text.strip();
        return text.length() > SNIPPET_MAX_LENGTH ? text.substring(0, SNIPPET_MAX_LENGTH) + "..." : text;
    }

    static String extension(String fileName) {
        int dot = fileName.lastIndexOf('.');
        return dot < 0 ? "" : fileName.substring(dot + 1).toLowerCase();
    }

    private static List<Path> files(Path root, Set<String> extensions) {
        try (Stream<Path> walk = Files.walk(root, MAX_DEPTH)) {
            return walk.filter(Files::isRegularFile)
                    .filter(p -> !Files.isSymbolicLink(p))
                    .filter(p -> extensions.contains(extension(p.getFileName().toString())))
                    .filter(p -> !skipped(root.relativize(p)))
                    .filter(p -> p.toFile().length() <= MAX_FILE_BYTES)
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("소스 파일을 찾지 못함: " + e.getMessage(), e);
        }
    }

    /** 빌드 결과물·의존성 폴더와 src/test 같은 테스트 소스는 건너뛴다 */
    public static boolean skipped(Path relative) {
        for (int i = 0; i < relative.getNameCount() - 1; i++) {
            String part = relative.getName(i).toString();
            if (SKIP_DIRS.contains(part)) {
                return true;
            }
            if (part.equals("src") && i + 1 < relative.getNameCount() - 1 && TEST_DIRS.contains(relative.getName(i + 1).toString())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isComment(String trimmed) {
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*") || trimmed.startsWith("<!--")
                || trimmed.startsWith("#");
    }
}
