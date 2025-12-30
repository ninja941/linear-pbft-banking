package com.distributedsystems.pbft.util;



import com.distributedsystems.pbft.proto.PbftServiceGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.TimeUnit;
    @Slf4j
    public class GrpcChannelUtil {

        private static final int DEFAULT_DEADLINE_MS = 1200;

        public static PbftServiceGrpc.PbftServiceBlockingStub createBlockingStub(String host, int port) {
            try {
                ManagedChannel channel = ManagedChannelBuilder
                        .forAddress(host, port)
                        .usePlaintext()
                        .build();

                return PbftServiceGrpc.newBlockingStub(channel)
                        .withDeadlineAfter(DEFAULT_DEADLINE_MS, TimeUnit.MILLISECONDS);
            } catch (StatusRuntimeException e) {
                log.warn("Failed to create blocking stub for {}:{} ({})", host, port, e.getStatus());
                throw e;
            } catch (Exception ex) {
                log.error("Error creating gRPC stub for {}:{} -> {}", host, port, ex.getMessage());
                throw new RuntimeException(ex);
            }
        }

        public static GrpcConnection openConnection(String host, int port) {
            ManagedChannel channel = ManagedChannelBuilder
                    .forAddress(host, port)
                    .usePlaintext()
                    .build();

            PbftServiceGrpc.PbftServiceBlockingStub stub =
                    PbftServiceGrpc.newBlockingStub(channel)
                            .withDeadlineAfter(DEFAULT_DEADLINE_MS, TimeUnit.MILLISECONDS);

            return new GrpcConnection(channel, stub);
        }

        public static void closeChannel(ManagedChannel channel) {
            if (channel != null) {
                channel.shutdown();
                try {
                    channel.awaitTermination(500, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

        }


        public record GrpcConnection(ManagedChannel channel, PbftServiceGrpc.PbftServiceBlockingStub stub) {}
    }
