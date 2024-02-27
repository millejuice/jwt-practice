package com.example.jwtprac.user;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

public class UserRequestDto {
    @Getter
    @Setter
    @Builder
    public static class SignInRequest{
        private String username;
        private String password;
    }
}
