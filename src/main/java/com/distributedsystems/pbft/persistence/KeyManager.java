package com.distributedsystems.pbft.persistence;

import com.distributedsystems.pbft.model.DecrypterEntity;
import com.distributedsystems.pbft.model.EncrypterEntity;
import com.distributedsystems.pbft.repository.IDecrypterEntity;
import com.distributedsystems.pbft.repository.IEncrypterEntity;
import com.distributedsystems.pbft.state.NodeState;
import com.distributedsystems.pbft.util.CryptoUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeyManager {

    private final IEncrypterEntity privateRepository;
    private final IDecrypterEntity publicRepository;
    private final NodeState nodeState;

    private volatile PrivateKey selfPrivateKey;
    private final Map<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() throws Exception {
        loadSelfPrivateKey();
        loadPublicKeys();
    }

    public PrivateKey selfPrivateKey() {
        return selfPrivateKey;
    }

    public PublicKey publicKeyOf(String nodeId) {
        PublicKey pk = publicKeyCache.get(nodeId);
        return pk;
    }

    private void loadSelfPrivateKey() throws Exception {
        String self = nodeState.getSelfNodeId();
        EncrypterEntity row = privateRepository.findById(self)
                .orElseThrow(() -> new IllegalStateException("Missing private key for " + self));
        selfPrivateKey = CryptoUtil.privateKeyFromBase64(row.getPrivateKey());
    }

    private void loadPublicKeys() throws Exception {
        publicKeyCache.clear();
        for (DecrypterEntity e : publicRepository.findAll()) {
            publicKeyCache.put(e.getNodeId(), CryptoUtil.publicKeyFromBase64(e.getPublicKey()));
        }
    }
}
