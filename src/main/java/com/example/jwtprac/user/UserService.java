package com.example.jwtprac.user;

import com.example.jwtprac.jwt.JwtToken;
import com.example.jwtprac.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo userRepo;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @Transactional
    public JwtToken signin(String username,String password){
//        username + password 기반으로 authentication 객체를 생성, 이때 authenticated 값은 false
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
//        실제로 검증이 이루어지는 부분 -> authenticate method 실행될 때 CustomUserDetailsService의 loadUserByUsername 메소드 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
//        인증 정보를 기반으로 JWT 토큰 생성
        JwtToken jwtToken = jwtTokenProvider.generateToken(authentication);

        return jwtToken;
    }
}
