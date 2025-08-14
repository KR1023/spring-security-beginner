package com.springsecurity.jwt;

import com.springsecurity.auth.CustomUserDetailsService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException
    {
        String header = req.getHeader("Authorization");
        if(StringUtils.hasText(header) && header.startsWith("Bearer")) {
            String token = header.substring(7);
            try {
                var claims = jwtService.parseToken(token).getBody();
                String username = claims.getSubject();

                // (선택) UserDetails 로드하여 계정 상태 확인
                UserDetails user = userDetailsService.loadUserByUsername(username);

                var authorities = jwtService.getRoles(token).stream()
                        .map(SimpleGrantedAuthority::new).toList();

                var auth = new UsernamePasswordAuthenticationToken(user, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception e) {
                // 유효하지 않은 토큰 -> 그냥 통과(다음 단계에서 401처리됨)
                SecurityContextHolder.clearContext();
            }
        }

        chain.doFilter(req, res);
    }
}
