package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.proto.ClientRequest;
import com.distributedsystems.pbft.repository.IDecrypterEntity;
import com.distributedsystems.pbft.util.CryptoUtil;
import com.google.protobuf.ByteString;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Component
@RequiredArgsConstructor
public class ClientRequestAuthenticator {

    private final IDecrypterEntity decrypterRepository;
    private final ClientKeyStore clientKeyStore;

    private final ConcurrentMap<String, PrivateKey> privateKeyCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, PublicKey>  publicKeyCache  = new ConcurrentHashMap<>();
    private static final Pattern DIGIT_EXTRACTOR = Pattern.compile(".*?(\\d+).*");

    public ClientRequest sign(ClientRequest.Builder builder) {
        if (builder == null) {
            throw new IllegalArgumentException("");
        }
        if (!requiresSignature(builder.getOperation())) {
            builder.clearClientDigest();
            builder.clearClientSignature();
            return builder.build();
        }

        String clientId = normalize(builder.getClientId());
        if (clientId.isBlank()) {
            throw new IllegalStateException("");
        }

        String canonical = canonicalPayload(
                clientId,
                builder.getOperation(),
                builder.getFromAccount(),
                builder.getToAccount(),
                builder.getAmount(),
                builder.getTimestamp()
        );

        String digest = CryptoUtil.sha256Base64(canonical);
        String signatureB64 = CryptoUtil.signBase64(canonical, resolvePrivateKey(clientId));

        builder.setClientDigest(digest);
        builder.setClientSignature(ByteString.copyFromUtf8(signatureB64));
        return builder.build();
    }

    public void verify(ClientRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("");
        }
        if (!requiresSignature(request.getOperation())) {
            return;
        }

        String clientId = normalize(request.getClientId());
        if (clientId.isBlank()) {
            throw new IllegalStateException("");
        }
        if (request.getClientSignature() == null || request.getClientSignature().isEmpty()) {
            throw new IllegalStateException(" " + clientId);
        }
        if (request.getClientDigest() == null || request.getClientDigest().isBlank()) {
            throw new IllegalStateException("" + clientId);
        }

        String canonical = canonicalPayload(request);
        String expectedDigest = CryptoUtil.sha256Base64(canonical);
        if (!expectedDigest.equals(request.getClientDigest())) {
            throw new IllegalStateException("" + clientId);
        }

        String signatureB64 = request.getClientSignature().toStringUtf8();
        if (!verifyWithCandidates(clientId, canonical, signatureB64)) {
            throw new IllegalStateException("" + clientId);
        }
    }

    private PrivateKey resolvePrivateKey(String clientId) {
        return privateKeyCache.computeIfAbsent(clientId, id -> {
            PrivateKey key = clientKeyStore.loadPrivateKeyBase64(id)
                    .map(raw -> {
                        try {
                            return CryptoUtil.privateKeyFromBase64(raw);
                        } catch (Exception e) {
                            throw new IllegalStateException("" + id, e);
                        }
                    })
                    .orElseThrow(() -> new IllegalStateException(" " + id));

            aliasOf(id).ifPresent(alias -> privateKeyCache.putIfAbsent(alias, key));
            return key;
        });
    }

    private boolean verifyWithCandidates(String clientId, String canonical, String signatureB64) {
        for (String candidate : candidates(clientId)) {
            PublicKey key = resolvePublicKey(candidate);
            if (key != null && CryptoUtil.verifyBase64(canonical, signatureB64, key)) {
                return true;
            }

            Optional<PublicKey> derived = clientKeyStore.derivePublicKey(candidate);
            if (derived.isPresent()) {
                PublicKey derivedKey = derived.get();
                publicKeyCache.putIfAbsent(candidate, derivedKey);
                if (CryptoUtil.verifyBase64(canonical, signatureB64, derivedKey)) {
                    return true;
                }
            }
        }
        return false;
    }

    private PublicKey resolvePublicKey(String clientId) {
        return publicKeyCache.computeIfAbsent(clientId, id -> {
            var candidates = candidates(id);
            for (String candidate : candidates) {
                PublicKey key = lookupPublicKey(candidate);
                if (key == null) {
                    key = clientKeyStore.derivePublicKey(candidate).orElse(null);
                    if (key != null) {
                    }
                }
                if (key != null) {
                    if (!candidate.equals(id)) {
                        publicKeyCache.putIfAbsent(candidate, key);
                    }
                    return key;
                }
            }
            throw new IllegalStateException("" + id);
        });
    }

    private PublicKey lookupPublicKey(String id) {
        if (id == null || id.isBlank()) return null;
        return decrypterRepository.findById(id)
                .map(row -> {
                    try {
                        return CryptoUtil.publicKeyFromBase64(row.getPublicKey());
                    } catch (Exception e) {
                        throw new IllegalStateException(" " + id, e);
                    }
                })
                .orElse(null);
    }

    private static String canonicalPayload(ClientRequest request) {
        return canonicalPayload(
                request.getClientId(),
                request.getOperation(),
                request.getFromAccount(),
                request.getToAccount(),
                request.getAmount(),
                request.getTimestamp()
        );
    }

    public static String canonicalPayload(String clientId,
                                          String operation,
                                          String fromAccount,
                                          String toAccount,
                                          long amount,
                                          String timestamp) {
        return new StringBuilder()
                .append(normalize(clientId)).append('|')
                .append(normalize(operation)).append('|')
                .append(normalize(fromAccount)).append('|')
                .append(normalize(toAccount)).append('|')
                .append(amount).append('|')
                .append(normalize(timestamp))
                .toString();
    }

    private static boolean requiresSignature(String operation) {
        return operation == null
                || operation.isBlank()
                || !"NOOP".equalsIgnoreCase(operation.trim());
    }

    private Set<String> candidates(String clientId) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        digitsVariant(clientId).ifPresent(values::add);
        aliasOf(clientId).flatMap(this::digitsVariant).ifPresent(values::add);
        values.add(clientId);
        aliasOf(clientId).ifPresent(values::add);
        values.removeIf(v -> v == null || v.isBlank());
        return values;
    }

    private Optional<String> aliasOf(String input) {
        if (input == null) return Optional.empty();
        int dash = input.indexOf('-');
        if (dash > 0) {
            return Optional.of(input.substring(0, dash));
        }
        return Optional.empty();
    }

    private Optional<String> digitsVariant(String input) {
        if (input == null || input.isBlank()) return Optional.empty();
        Matcher m = DIGIT_EXTRACTOR.matcher(input);
        if (m.matches()) {
            return Optional.of("client" + m.group(1));
        }
        return Optional.empty();
    }

    private static String normalize(String input) {
        return input == null ? "" : input;
    }
}
