package com.distributedsystems.pbft.util;

import com.distributedsystems.pbft.proto.*;

public interface IValidator {

    boolean validateClientRequest(ClientRequest req);

    boolean validatePrePrepare(PrePrepare msg);
    boolean validatePrepare(Prepare msg);
    boolean validateCommitCertificate(CommitCertificate cert);

    boolean hasPrepareCertificate(long seqNo, String digest);
    boolean digestMatches(byte[] payload, String digestB64);
    boolean checkViewAndSequence(long view, long seqNo);

    boolean hasQuorumForPrepare(long view, long seqNo, String digest);
    boolean validatePrepareCertificate(PrepareCertificate cert);
    boolean validateCommit(Commit commit);

    CommitCertificate appendSignature(CommitCertificate cert, Commit myCommit);
}
