package com.distributedsystems.pbft.service;

import com.distributedsystems.pbft.model.DecrypterEntity;
import com.distributedsystems.pbft.model.EncrypterEntity;
import com.distributedsystems.pbft.repository.IDecrypterEntity;
import com.distributedsystems.pbft.repository.IEncrypterEntity;
import com.distributedsystems.pbft.state.NodeState;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP;
import org.apache.milagro.amcl.BLS381.ECP2;
import org.apache.milagro.amcl.BLS381.FP12;
import org.apache.milagro.amcl.BLS381.PAIR;
import org.apache.milagro.amcl.BLS381.ROM;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class ThresholdSignatureService {

    public enum SharePhase {
        PREPARE("PREPARE"),
        COMMIT("COMMIT");

        private final String tag;

        SharePhase(String tag) {
            this.tag = tag;
        }

        public String tag() {
            return tag;
        }
    }

    private static final int G1_BYTES = 2 * BIG.MODBYTES + 1;

    private final IEncrypterEntity encrypterRepository;
    private final IDecrypterEntity decrypterRepository;
    private final NodeState nodeState;

    @Value("${pbft.optimizations.bonus_2.enabled:false}")
    private boolean bonus2Enabled;

    private final Map<String, KeyMaterial> keyCache = new ConcurrentHashMap<>();
    private final Map<ShareKey, ConcurrentHashMap<String, byte[]>> shareStore = new ConcurrentHashMap<>();

    private byte[] groupPublicKeyBytes;
    private ECP2 groupPublicKey;

    @PostConstruct
    void loadGroupPublicKey() {
        if (!bonus2Enabled) return;
        decrypterRepository.findAll().stream()
                .map(DecrypterEntity::getThresholdGroupPublic)
                .filter(s -> s != null && !s.isBlank())
                .findFirst()
                .ifPresent(raw -> {
                    try {
                        groupPublicKeyBytes = Base64.getDecoder().decode(raw);
                    } catch (Exception e) {
                        log.warn("[ThresholdSig] Unable to decode group public key: {}", e.getMessage());
                    }
                });
    }

    public boolean isEnabled() {
        return bonus2Enabled && groupPublicKeyBytes != null;
    }

    public Optional<byte[]> createPartialSignature(SharePhase phase,
                                                   long view,
                                                   long sequence,
                                                   String digest,
                                                   String replicaId) {
        if (!isEnabled()) return Optional.empty();
        KeyMaterial material = resolveMaterial(replicaId);
        if (material == null || material.privateShare == null) {
            return Optional.empty();
        }
        try {
            ECP hashPoint = hashToPoint(canonicalMessage(phase, view, sequence, digest));
            ECP sig = hashPoint.mul(material.privateShare);
            byte[] bytes = new byte[G1_BYTES];
            sig.toBytes(bytes, true);
            return Optional.of(bytes);
        } catch (Exception e) {
            log.warn("[ThresholdSig] Failed to produce partial signature for {}: {}", replicaId, e.getMessage());
            return Optional.empty();
        }
    }

    public void registerShare(SharePhase phase,
                              long view,
                              long sequence,
                              String digest,
                              String replicaId,
                              byte[] shareBytes) {
        if (!isEnabled() || shareBytes == null || shareBytes.length == 0) return;
        KeyMaterial material = resolveMaterial(replicaId);
        if (material == null || material.publicShare == null) {
            log.debug("[ThresholdSig] Missing public share for {} → skipping threshold share", replicaId);
            return;
        }

        byte[] message = canonicalMessage(phase, view, sequence, digest);
        if (!verifyShare(material.publicShare, shareBytes, message)) {
            log.warn("[ThresholdSig] Invalid threshold share from {}", replicaId);
            return;
        }

        ShareKey key = new ShareKey(phase, view, sequence, digest);
        shareStore.computeIfAbsent(key, k -> new ConcurrentHashMap<>())
                .put(replicaId, shareBytes);
    }

    public Optional<byte[]> tryAggregate(SharePhase phase,
                                         long view,
                                         long sequence,
                                         String digest) {
        if (!isEnabled()) return Optional.empty();
        ShareKey key = new ShareKey(phase, view, sequence, digest);
        Map<String, byte[]> shares = shareStore.getOrDefault(key, new ConcurrentHashMap<>());
        if (shares.size() < nodeState.quorumSize()) {
            return Optional.empty();
        }

        try {
            byte[] message = canonicalMessage(phase, view, sequence, digest);
            byte[] aggregated = aggregateShares(message, shares);
            shareStore.remove(key);
            return Optional.ofNullable(aggregated);
        } catch (Exception e) {
            log.warn("[ThresholdSig] Aggregation failed for seq {} view {}: {}", sequence, view, e.getMessage());
            shareStore.remove(key);
            return Optional.empty();
        }
    }

    public boolean verifyAggregatedSignature(SharePhase phase,
                                             long view,
                                             long sequence,
                                             String digest,
                                             byte[] aggregatedSignature) {
        if (!isEnabled() || aggregatedSignature == null || aggregatedSignature.length == 0) return false;
        try {
            ECP sig = ECP.fromBytes(aggregatedSignature);
            ECP2 pub = groupPublicKey;
            if (pub == null && groupPublicKeyBytes != null) {
                pub = ECP2.fromBytes(groupPublicKeyBytes);
                groupPublicKey = pub;
            }
            if (pub == null) {
                log.warn("[ThresholdSig] Missing group public key for verification");
                return false;
            }
            ECP hash = hashToPoint(canonicalMessage(phase, view, sequence, digest));
            FP12 left = PAIR.fexp(PAIR.ate(ECP2.generator(), sig));
            FP12 right = PAIR.fexp(PAIR.ate(pub, hash));
            return left.equals(right);
        } catch (Exception e) {
            log.warn("[ThresholdSig] Aggregated signature verification failed: {}", e.getMessage());
            return false;
        }
    }

    private byte[] aggregateShares(byte[] message, Map<String, byte[]> shares) {
        Collection<Map.Entry<String, byte[]>> entries = shares.entrySet();
        if (entries.isEmpty()) return null;

        ECP accumulator = new ECP();
        accumulator.inf();
        Set<Integer> participantIds = shares.keySet().stream()
                .map(this::extractNodeIndex)
                .filter(id -> id > 0)
                .collect(java.util.stream.Collectors.toSet());
        if (participantIds.size() < nodeState.quorumSize()) {
            return null;
        }
        BIG order = new BIG(ROM.CURVE_Order);

        for (Map.Entry<String, byte[]> entry : entries) {
            int participant = extractNodeIndex(entry.getKey());
            if (participant <= 0) continue;
            ECP sharePoint = ECP.fromBytes(entry.getValue());
            BIG coefficient = lagrangeCoefficient(participant, participantIds, order);
            sharePoint = sharePoint.mul(coefficient);
            accumulator.add(sharePoint);
        }
        accumulator.affine();
        byte[] out = new byte[G1_BYTES];
        accumulator.toBytes(out, true);
        return out;
    }

    private BIG lagrangeCoefficient(int participant,
                                    Set<Integer> participants,
                                    BIG order) {
        BIG numerator = new BIG(1);
        BIG denominator = new BIG(1);
        BIG bi = new BIG(participant);

        for (int other : participants) {
            if (other == participant) continue;
            BIG bj = new BIG(other);
            numerator = BIG.modmul(numerator, bj, order);
            BIG diff = new BIG(other);
            diff.sub(bi);
            diff.mod(order);
            denominator = BIG.modmul(denominator, diff, order);
        }

        BIG inv = new BIG(denominator);
        inv.invmodp(order);
        return BIG.modmul(numerator, inv, order);
    }

    private boolean verifyShare(ECP2 publicShare, byte[] signature, byte[] message) {
        try {
            ECP sigPoint = ECP.fromBytes(signature);
            ECP hashPoint = hashToPoint(message);
            FP12 left = PAIR.fexp(PAIR.ate(publicShare, hashPoint));
            FP12 right = PAIR.fexp(PAIR.ate(ECP2.generator(), sigPoint));
            return left.equals(right);
        } catch (Exception e) {
            log.warn("[ThresholdSig] Share verification failed: {}", e.getMessage());
            return false;
        }
    }

    private ECP hashToPoint(byte[] payload) throws NoSuchAlgorithmException {
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
        byte[] digest = sha3.digest(payload);
        return ECP.mapit(digest);
    }

    private byte[] canonicalMessage(SharePhase phase, long view, long seq, String digest) {
        String msg = phase.tag() + "|" + view + "|" + seq + "|" + digest;
        return msg.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private KeyMaterial resolveMaterial(String nodeId) {
        if (nodeId == null) return null;
        return keyCache.computeIfAbsent(nodeId, this::loadMaterial);
    }

    private KeyMaterial loadMaterial(String nodeId) {
        try {
            Optional<EncrypterEntity> encOpt = encrypterRepository.findById(nodeId);
            Optional<DecrypterEntity> decOpt = decrypterRepository.findById(nodeId);
            if (encOpt.isEmpty() || decOpt.isEmpty()) return KeyMaterial.empty();

            EncrypterEntity enc = encOpt.get();
            DecrypterEntity dec = decOpt.get();

            BIG privateShare = null;
            if (enc.getThresholdPrivateShare() != null && !enc.getThresholdPrivateShare().isBlank()) {
                byte[] shareBytes = Base64.getDecoder().decode(enc.getThresholdPrivateShare());
                privateShare = BIG.fromBytes(shareBytes);
            }

            ECP2 publicShare = null;
            if (dec.getThresholdPublicShare() != null && !dec.getThresholdPublicShare().isBlank()) {
                byte[] bytes = Base64.getDecoder().decode(dec.getThresholdPublicShare());
                publicShare = ECP2.fromBytes(bytes);
            }

            if (dec.getThresholdGroupPublic() != null && !dec.getThresholdGroupPublic().isBlank()) {
                byte[] raw = Base64.getDecoder().decode(dec.getThresholdGroupPublic());
                groupPublicKeyBytes = raw;
                groupPublicKey = ECP2.fromBytes(raw);
            }

            return new KeyMaterial(privateShare, publicShare);
        } catch (Exception e) {
            log.warn("[ThresholdSig] Failed to load key material for {}: {}", nodeId, e.getMessage());
            return KeyMaterial.empty();
        }
    }

    private int extractNodeIndex(String nodeId) {
        if (nodeId == null) return -1;
        try {
            if (nodeId.startsWith("node-")) {
                return Integer.parseInt(nodeId.substring(5));
            }
            return Integer.parseInt(nodeId);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private record KeyMaterial(BIG privateShare, ECP2 publicShare) {
        static KeyMaterial empty() {
            return new KeyMaterial(null, null);
        }
    }

    private record ShareKey(SharePhase phase, long view, long sequence, String digest) {
    }

    public void reset() {
        shareStore.clear();
    }
}
