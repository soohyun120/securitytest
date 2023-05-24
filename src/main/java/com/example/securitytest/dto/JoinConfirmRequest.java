package com.example.securitytest.dto;

import lombok.Data;

@Data
public class JoinConfirmRequest {
    private String email;
    private String authToken;
}
