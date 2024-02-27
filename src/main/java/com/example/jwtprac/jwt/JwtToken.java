package com.example.jwtprac.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class JwtToken {
    private String grantType; //인증 타입 - bearer
    private String accessToken;
    private String refreshToken;
}
