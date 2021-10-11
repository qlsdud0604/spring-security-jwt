package com.example.springsecurityjwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.springsecurityjwt.config.auth.PrincipalDetails;
import com.example.springsecurityjwt.model.User;
import com.example.springsecurityjwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);

        this.userRepository = userRepository;
    }

    @Override
    /** 인증이나 권한이 필요한 주소요청이 있을 때 실행되는 메서드 */
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " + jwtHeader);

        /* 클라이언트 측에서 전달받은 JWT가 올바른지 확인 */
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        /* 클라이언트 측에서 전달받은 JWT 검증 */
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        String username = JWT.require(Algorithm.HMAC512("qlsdud0604")).build().verify(jwtToken).getClaim("username").asString();

        /* JWT 검증이 올바르게 된 경우 */
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);   // 시큐리티 세션 공간에 Authentication 저장

            chain.doFilter(request, response);
        }
    }
}

// 1. 시큐리티가 필터를 가지고 있는데, 그 필터중에 BasicAuthenticationFilter 라는 것이 있음
// 2. 권한이나 인증이 필요한 특정 주소를 요청했을 때 해당 필터를 무조건 거침
// 3. 만약에 권한이나 인증이 필요한 주소가 아니라면 해당 필터를 거치지 않음
