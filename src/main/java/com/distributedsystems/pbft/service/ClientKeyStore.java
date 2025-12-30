package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.model.ClientPrivateKeyEntity;
import com.distributedsystems.pbft.repository.IClientPrivateKeyRepository;
import com.distributedsystems.pbft.util.CryptoUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
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
public class ClientKeyStore {

    private final IClientPrivateKeyRepository privateKeyRepository;
    private final ConcurrentMap<String, String> cache = new ConcurrentHashMap<>();

    private static final Pattern DIGIT_EXTRACTOR = Pattern.compile(".*?(\\d+).*");

    public Optional<String> loadPrivateKeyBase64(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return Optional.empty();
        }

        var candidates = candidates(clientId);
        for (String candidate : candidates) {
            String value = resolveKey(candidate);
            if (value != null && !value.isBlank()) {
                return Optional.of(value);
            }
        }
        return Optional.empty();
    }

    private String resolveKey(String id) {
        return cache.computeIfAbsent(id, key -> privateKeyRepository.findById(key)
                .map(ClientPrivateKeyEntity::getPrivateKey)
                .map(String::trim)
                .orElse(null));
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

    private Optional<String> aliasOf(String clientId) {
        if (clientId == null) return Optional.empty();
        int dash = clientId.indexOf('-');
        if (dash > 0) {
            return Optional.of(clientId.substring(0, dash));
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

    public Optional<PublicKey> derivePublicKey(String clientId) {
        return loadPrivateKeyBase64(clientId)
                .map(this::decodePrivate)
                .flatMap(this::publicFromPrivate);
    }

    private Optional<PublicKey> publicFromPrivate(PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey rsa)) {
            return Optional.empty();
        }
        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent());
            return Optional.of(KeyFactory.getInstance("RSA").generatePublic(spec));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private PrivateKey decodePrivate(String base64) {
        try {
            return CryptoUtil.privateKeyFromBase64(base64);
        } catch (Exception e) {
            throw new IllegalStateException("", e);
        }
    }
}
