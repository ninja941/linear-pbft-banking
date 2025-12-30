package com.distributedsystems.pbft.util;

import com.distributedsystems.pbft.proto.CheckpointSummary;
import com.distributedsystems.pbft.proto.PrePrepare;
import com.distributedsystems.pbft.proto.PreparedEntry;
import com.distributedsystems.pbft.proto.ViewChange;

import java.util.Collection;
import java.util.Comparator;
import java.util.stream.Collectors;

public final class ViewChangeCodec {

    public static String preparedEntriesDigest(Collection<PreparedEntry> entries) {
        return entries.stream()
                .sorted(Comparator.comparingLong(PreparedEntry::getSequence))
                .map(e -> e.getSequence() + ":" + e.getView() + ":" + e.getDigest())
                .collect(Collectors.joining(","));
    }

    public static String viewChangesDigest(Collection<ViewChange> changes) {
        return changes.stream()
                .sorted(Comparator.comparing(ViewChange::getReplicaId))
                .map(vc -> vc.getReplicaId() + "#" +
                        checkpointDigest(vc.hasCheckpoint() ? vc.getCheckpoint() : null) + "#" +
                        preparedEntriesDigest(vc.getPreparedMessagesList()))
                .collect(Collectors.joining("|"));
    }

    public static String prePrepareDigest(Collection<PrePrepare> pres) {
        return pres.stream()
                .sorted(Comparator.comparingLong(PrePrepare::getSequence))
                .map(pre -> pre.getSequence() + ":" + pre.getDigest())
                .collect(Collectors.joining(","));
    }

    public static String checkpointDigest(CheckpointSummary summary) {
        if (summary == null) return "";
        String d = summary.getDigest();
        if (d != null && !d.isBlank()) {
            return d;
        }
        String payload = summary.getSequence() + "|" + summary.getLabel();
        return CryptoUtil.digest(payload);
    }
}
