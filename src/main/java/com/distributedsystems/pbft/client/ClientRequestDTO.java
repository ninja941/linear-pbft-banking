package com.distributedsystems.pbft.client;


import lombok.Data;

@Data
public class ClientRequestDTO {
    private String clientId;
    private String fromAccount;
    private String toAccount;
    private long amount;
    private String timestamp;
    private String operation;
}
