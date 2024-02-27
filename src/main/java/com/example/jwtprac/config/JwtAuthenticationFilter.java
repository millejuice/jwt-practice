package com.example.jwtprac.config;

import com.example.jwtprac.jwt.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

// client에서 request하면 Jwt 인증하기 위한 custom filter -> UserNamePasswordAuthenticationFilter보다 먼저 실행
//유효한 토큰이면 Authentication을 SecurityContext에 저장
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = resolveToken((HttpServletRequest) request); //Request Header에서 JWT 꺼내오기
        if (token != null && jwtTokenProvider.validateToken(token)) { //token이 존재하고, 유효한 경우일 때
            Authentication authentication = jwtTokenProvider.getAuthentication(token); //Authentication 객체 가져와서 security context에 저장 -> 요청 처리하는동안 인증정보 유지
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response); //다음 필터로 넘기기
    }

//    Request Header에서 토큰 정보 꺼내오기
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) { //Bearer로 시작하는 토큰 추출하여 반환
            return bearerToken.substring(7);
        }
        return null;
    }
}
