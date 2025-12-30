package com.distributedsystems.pbft.util;

import com.distributedsystems.pbft.proto.ClientRequest;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
@Component
public class DigestUtil {


    public static String computeDigest(ClientRequest req) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String data = req.getClientId() + req.getOperation() + req.getTimestamp();
            return HexFormat.of().formatHex(md.digest(data.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute digest", e);
        }
    }
}
