package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.state.NodeState;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
@Service
public class ByzantineService {

    private static final String DARK_ATTACK_TIMER_REASON = "dark-attack";

    @Getter
    private String activeAttack = "";
    private final Set<Integer> byzantineNodes = Collections.synchronizedSet(new LinkedHashSet<>());
    private final Set<String> crashedNodes = ConcurrentHashMap.newKeySet();
    private final Set<Integer> darkVictims = ConcurrentHashMap.newKeySet();
    private final Set<Integer> equivocateVictims = ConcurrentHashMap.newKeySet();
    private final Set<String> activeAttackModes = ConcurrentHashMap.newKeySet();
    private final Set<String> nodesWithLoggedCorruption = ConcurrentHashMap.newKeySet();
    private final Set<String> nodesWithLoggedDelay = ConcurrentHashMap.newKeySet();


    @Autowired @Lazy
    private NodeState nodeState;

    @Autowired(required = false) @Lazy
    private PbftTimerService pbftTimerService;


    public boolean shouldBlockServerInbound(String selfId) {
        return false;
    }

    public boolean shouldBlockClientOutbound(String selfId) {
        return false;
    }

    @Value("${pbft.attacks.time-delay-fraction:0.3}")
    private double timeDelayFraction;

    @Value("${pbft.timers.activity-timeout-ms:3000}")
    private long activityTimeoutMs;

    @Value("${pbft.attacks.dark.activity-timeout-ms:1000}")
    private long darkActivityTimeoutMs;

    @Value("${pbft.timers.progress-timeout-ms:5000}")
    private long progressTimeoutMs;

    public synchronized void configureAttack(String attackDirective,
                                             Set<Integer> attackerNodes,
                                             Set<Integer> victims) {
        activeAttackModes.clear();
        darkVictims.clear();
        equivocateVictims.clear();
        crashedNodes.clear();
        byzantineNodes.clear();
        nodesWithLoggedDelay.clear();
        if (attackerNodes != null) {
            byzantineNodes.addAll(attackerNodes);
        }

        var modes = parseAttackModes(attackDirective);
        activeAttackModes.addAll(modes);
        activeAttack = activeAttackModes.isEmpty()
                ? ""
                : String.join(",", activeAttackModes);

        if (isModeActive("crash") && attackerNodes != null) {
            attackerNodes.forEach(id -> crashedNodes.add(canonicalId(id)));
            log.warn("[ByzantineService] CRASH attack → silencing nodes {}", crashedNodes);
        }

        if (attackDirective != null && !attackDirective.isBlank()) {
            extractVictims(attackDirective, "dark").forEach(darkVictims::add);
            extractVictims(attackDirective, "equivocate").forEach(equivocateVictims::add);
        }


        if (isModeActive("time")) {
            long baseline = baselineTimerMs();
            long delay = computeTimeDelayMillisInternal(baseline);
            log.warn("[ByzantineService] TIME attack configured for nodes {} (delay={}ms baseline={}ms fraction={})",
                    byzantineNodes, delay, baseline, String.format(Locale.ROOT, "%.2f", normalizedDelayFraction()));
        }



        refreshDarkModeTimerOverride();
    }

    public synchronized void clearAttack() {
        if (!activeAttackModes.isEmpty() || !crashedNodes.isEmpty()) {
        }
        activeAttack = "";
        activeAttackModes.clear();
        byzantineNodes.clear();
        crashedNodes.clear();
        darkVictims.clear();
        equivocateVictims.clear();
        nodesWithLoggedCorruption.clear();
        nodesWithLoggedDelay.clear();

        if (nodeState != null) {
            nodeState.setParticipating(true);
        }

        refreshDarkModeTimerOverride();
    }

    public boolean isCrashed(String nodeId) {
        String canonical = canonicalId(nodeId);
        return canonical != null && crashedNodes.contains(canonical);
    }

    public boolean isByzantine(String nodeId) {
        int idNum = extractNodeNum(nodeId);
        return idNum >= 0 && byzantineNodes.contains(idNum);
    }

    public boolean shouldSuppressSend(String senderId, String targetId) {
        if (!isModeActive("dark")) {
            return false;
        }
        if (!isByzantine(senderId)) {
            return false;
        }
        if (darkVictims.isEmpty()) {
            return false;
        }
        if (targetId == null) {
            return false;
        }
        int targetNum = extractNodeNum(targetId);
        return targetNum >= 0 && darkVictims.contains(targetNum);
    }

    public boolean shouldSuppressSend(String nodeId) {
        return false;
    }

    public boolean shouldCorruptSignature(String nodeId) {
        return isModeActive("sign") && isByzantine(nodeId);
    }

    public String maybeCorruptSignature(String nodeId, String originalSignature) {
        if (!shouldCorruptSignature(nodeId)) {
            return originalSignature;
        }
        String canonical = canonicalId(nodeId);
        if (canonical != null && nodesWithLoggedCorruption.add(canonical)) {
            log.warn("[ByzantineService] SIGN attack → corrupting signatures from {}", canonical);
        }
        String payload = "corrupt|" + (canonical != null ? canonical : nodeId) + "|" + System.nanoTime();
        return Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    }

    public boolean isModeActive(String mode) {
        if (mode == null) return false;
        return activeAttackModes.contains(mode.toLowerCase(Locale.ROOT));
    }

    public boolean isEquivocateVictim(String targetId) {
        int id = extractNodeNum(targetId);
        return id >= 0 && equivocateVictims.contains(id);
    }

    public synchronized void markSelfCrashed(String nodeId, String attackType) {
        var modes = parseAttackModes(attackType);
        if (!modes.isEmpty()) {
            activeAttackModes.addAll(modes);
            activeAttack = String.join(",", activeAttackModes);
        } else if (activeAttackModes.isEmpty()) {
            activeAttackModes.add("crash");
            activeAttack = "crash";
        }

        int nodeNum = extractNodeNum(nodeId);
        if (nodeNum >= 0) {
            byzantineNodes.add(nodeNum);
        }
        String canonical = canonicalId(nodeId);
        if (canonical != null) {
            boolean shouldSilence = isModeActive("crash");
            if (shouldSilence) {
                crashedNodes.add(canonical);
                log.warn("[ByzantineService] Self-activated '{}' attack for {} (node remains in view, suppressing PREPARE/NEW-VIEW)", activeAttack, canonical);
            } else {
                log.warn("[ByzantineService] Self-activated '{}' attack for {} (node remains online)", activeAttack, canonical);
            }
        }

        refreshDarkModeTimerOverride();
    }

    private static int extractNodeNum(String nodeId) {
        if (nodeId == null) return -1;
        String cleaned = nodeId.replaceAll("[^0-9]", "");
        return cleaned.isEmpty() ? -1 : Integer.parseInt(cleaned);
    }

    private static String canonicalId(int nodeNum) {
        return canonicalId("node-" + nodeNum);
    }

    private static String canonicalId(String nodeId) {
        if (nodeId == null) return null;
        String trimmed = nodeId.trim();
        if (trimmed.isEmpty()) return null;

        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (lower.startsWith("node-")) {
            return lower;
        }
        if (lower.startsWith("n") && lower.length() > 1) {
            return "node-" + lower.substring(1);
        }
        if (lower.matches("\\d+")) {
            return "node-" + lower;
        }
        return lower;
    }

    private static String normalizeAttack(String attackType) {
        return attackType == null ? "" : attackType.trim().toLowerCase(Locale.ROOT);
    }

    private static Set<String> parseAttackModes(String attackDirective) {
        String normalized = normalizeAttack(attackDirective);
        if (normalized.isBlank()) {
            return Collections.emptySet();
        }
        String[] tokens = normalized.split("[^a-z]+");
        Set<String> modes = new LinkedHashSet<>();
        Set<String> allow = new LinkedHashSet<>();
        Collections.addAll(allow, "equivocate", "equivocation", "dark", "crash", "time", "sign");
        for (String token : tokens) {
            if (!token.isBlank()) {
                String t = token;
                if ("equivocation".equals(t)) t = "equivocate";
                if (!allow.contains(t)) continue; // drop stray 'n' etc.
                modes.add(t);
            }
        }
        return modes;
    }

    private static Set<Integer> extractVictims(String directive, String keyword) {
        try {
            if (directive == null) return Collections.emptySet();
            String lower = directive.toLowerCase(Locale.ROOT);

            String canonical = keyword + "(";
            String synonym = ("equivocate".equals(keyword) ? "equivocation(" : null);

            Set<Integer> out = new LinkedHashSet<>();
            int from = 0;
            while (from < lower.length()) {
                int i = lower.indexOf(canonical, from);
                int j = (synonym == null) ? -1 : lower.indexOf(synonym, from);
                int p = -1;
                int openLen = 0;
                if (i < 0 && j < 0) break;
                if (i >= 0 && (j < 0 || i <= j)) { p = i; openLen = canonical.length(); }
                else { p = j; openLen = synonym.length(); }

                int start = p + openLen;
                int parenDepth = 1;
                int bracketDepth = 0;
                StringBuilder token = new StringBuilder();

                for (int idx = start; idx < lower.length(); idx++) {
                    char ch = lower.charAt(idx);
                    if (ch == '(') { parenDepth++; }
                    else if (ch == ')') {
                        parenDepth--;
                        if (parenDepth == 0) {
                            // flush last token at top-level
                            if (bracketDepth == 0 && token.length() > 0) {
                                addTokenAsNode(out, token.toString());
                                token.setLength(0);
                            }
                            from = p + 1;
                            break;
                        }
                    } else if (ch == '[') { bracketDepth++; }
                    else if (ch == ']') { if (bracketDepth > 0) bracketDepth--; }
                    if (parenDepth == 1 && bracketDepth == 0) {
                        if (Character.isLetterOrDigit(ch)) {
                            token.append(ch);
                        } else if (ch == ',' || Character.isWhitespace(ch)) {
                            if (token.length() > 0) {
                                addTokenAsNode(out, token.toString());
                                token.setLength(0);
                            }
                        }
                    }
                    if (idx == lower.length() - 1) {
                        from = idx + 1;
                    }
                }
                if (from <= p) {
                    from = p + openLen;
                }
            }
            return out;
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    private static void addTokenAsNode(Set<Integer> out, String token) {
        String t = token.trim();
        if (t.isEmpty()) return;
        String digits = t.replaceAll("[^0-9]", "");
        if (digits.isEmpty()) return;
        try { out.add(Integer.parseInt(digits)); } catch (Exception ignored) {}
    }

    public Set<Integer> getDarkVictims() {
        return Collections.unmodifiableSet(darkVictims);
    }

    public void maybeDelayPrimarySend(String nodeId, boolean isPrimary, String actionDescription) {
        if (!isPrimary || !isModeActive("time") || !isByzantine(nodeId)) {
            return;
        }
        long delay = computeTimeDelayMillis(nodeId);
        if (delay <= 0) {
            return;
        }
        String canonical = canonicalId(nodeId);
        if (canonical != null && nodesWithLoggedDelay.add(canonical)) {
            log.warn("[ByzantineService] TIME attack → delaying {} from {} by {}ms", actionDescription, canonical, delay);
        } else {
            log.debug("[ByzantineService] TIME attack → delaying {} from {} by {}ms", actionDescription,
                    canonical != null ? canonical : nodeId, delay);
        }
        try {
            Thread.sleep(delay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    public long computeTimeDelayMillis(String nodeId) {
        if (!isModeActive("time") || !isByzantine(nodeId)) {
            return 0L;
        }
        long baseline = baselineTimerMs();
        return computeTimeDelayMillisInternal(baseline);
    }

    private long computeTimeDelayMillisInternal(long baselineTimerMs) {
        if (baselineTimerMs <= 0L) {
            return 0L;
        }
        double fraction = normalizedDelayFraction();
        long requested = Math.round(baselineTimerMs * fraction);
        long maxSafe = Math.max(1L, baselineTimerMs - 250L);
        long clamped = Math.min(Math.max(0L, requested), maxSafe);
        return clamped;
    }

    private double normalizedDelayFraction() {
        double fraction = Double.isNaN(timeDelayFraction) ? 0.3 : timeDelayFraction;
        if (fraction < 0.0) {
            fraction = 0.0;
        }
        if (fraction > 0.9) {
            fraction = 0.9;
        }
        return fraction;
    }

    private long baselineTimerMs() {
        long activity = activityTimeoutMs;
        long progress = progressTimeoutMs;
        if (pbftTimerService != null) {
            activity = pbftTimerService.getActivityTimeoutMs();
            progress = pbftTimerService.getProgressTimeoutMs();
        }
        long safeActivity = activity <= 0 ? Long.MAX_VALUE : activity;
        long safeProgress = progress <= 0 ? Long.MAX_VALUE : progress;
        long candidate = Math.min(safeActivity, safeProgress);
        if (candidate == Long.MAX_VALUE) {
            return 0L;
        }
        return candidate;
    }

    public synchronized String describe() {
        return "ByzantineService{attack='" + activeAttack + "', nodes=" + byzantineNodes +
                ", crashed=" + crashedNodes + ", darkVictims=" + darkVictims +
                ", equivocateVictims=" + equivocateVictims + '}';
    }

    private void refreshDarkModeTimerOverride() {
        if (pbftTimerService == null) {
            return;
        }
        boolean darkActive = isModeActive("dark") && darkActivityTimeoutMs > 0L;
        if (darkActive) {
            long overrideMs = Math.max(250L, darkActivityTimeoutMs);
            pbftTimerService.overrideActivityTimeout(Duration.ofMillis(overrideMs), DARK_ATTACK_TIMER_REASON);
        } else {
            pbftTimerService.resetActivityTimeout(DARK_ATTACK_TIMER_REASON);
        }

        boolean forceActivityChecks = false;
        if (darkActive && nodeState != null) {
            String selfId = nodeState.getSelfNodeId();
            forceActivityChecks = isDarkVictim(selfId) && !isByzantine(selfId);
        }
        pbftTimerService.setForceActivityChecks(forceActivityChecks, DARK_ATTACK_TIMER_REASON);
    }

    private boolean isDarkVictim(String nodeId) {
        int nodeNum = extractNodeNum(nodeId);
        return nodeNum >= 0 && darkVictims.contains(nodeNum);
    }
}
