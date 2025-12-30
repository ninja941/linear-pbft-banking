package com.distributedsystems.pbft.util;

import com.distributedsystems.pbft.service.ByzantineService;
import com.distributedsystems.pbft.state.NodeState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class ByzantineInterceptor {

    @Autowired @Lazy
    private ByzantineService byz;

    @Autowired
    private NodeState nodeState;

    public ByzantineService getByzantineService() {
        return byz;
    }

    public boolean shouldSuppressSend(String nodeId) {
        return byz != null && byz.shouldSuppressSend(nodeId);
    }

    public boolean shouldBlock(String action) {
        return shouldBlock(action, null);
    }

    public boolean shouldBlock(String action, Object target) {
        if (nodeState == null) return false;

        String self = nodeState.getSelfNodeId();
        if (shouldSuppressSend(self)) {
            if (nodeState.isPrimary()) {
                log.error("[{}] Suppressing {} to {} — leader crashed under Byzantine attack", self, action, target);
                nodeState.markAsCrashedLeader();
            } else {
                log.warn("[{}] Suppressing {} to {} — node crashed under Byzantine attack", self, action, target);
            }
            return true;
        }

        return false;
    }
}
