package com.example.springsecurityjwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    /** /login 요청을 하면 로그인 시도를 위해서 실행되는 함수 */
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter 로그인 시도 중");

        // 1. username, password를 받음

        // 2. authenticationManager를 통해서 로그인 시도를 하면, PrincipalDetailsService가 호출되고 loadUserByUsername( ) 메서드 실행됨

        // 3. loadUserByUsername( ) 메서드에 의해서 반환되는 PrincipalDetails를 세션에 담음

        // 4. JWT를 만들어 응답을 해주면 됨

        return super.attemptAuthentication(request, response);
    }
}


// 1. /login 요청을 해서 username, password를 전송하면 UsernamePasswordAuthenticationFilter가 동작을 함
// 2. 하지만 현재 SecurityConfig 클래스에서 .formLogin().disable() 메서드를 통해 폼 로그인 미사용 설정을 했기 때문에 동작하지 않음
// 3. 따라서 SecurityConfig 클래스에 별도로 등록을 해주어야 함
// 4. AuthenticationManager 객체를 통해 로그인을 수행하기 때문에 AuthenticationManager 객체 또한 선을을 해야 함