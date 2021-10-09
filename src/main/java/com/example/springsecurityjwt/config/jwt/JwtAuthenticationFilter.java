package com.example.springsecurityjwt.config.jwt;

import com.example.springsecurityjwt.config.auth.PrincipalDetails;
import com.example.springsecurityjwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    /** /login 요청을 하면 로그인 시도를 위해서 실행되는 함수 */
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("==========JwtAuthenticationFilter 로그인 시도 중==========");

        try {
            /* JSON 데이터를 전달받고 User 객체로 매핑 */
            ObjectMapper mapper = new ObjectMapper();
            User user = mapper.readValue(request.getInputStream(), User.class);
            System.out.println("1. User 객체 매핑 완료 : " + user);

            /* User의 username과 password로 토큰 생성*/
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            System.out.println("2. 토큰 생성 완료");


            /* 토큰의 username을 통해 authenticationManager를 통해서 로그인 시도를 하면 PrincipalDetailsService의 loadUserByUsername() 메서드가 자동으로 실행 */
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            /* loadUserByUsername( ) 메서드가 정상적으로 실행되면 Authentication 객체가 리턴됨(DB에 있는 username과 password가 일치한다는 의미) */
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("3. 로그인 완료 : " + principalDetails.getUser().getUsername() + " " + principalDetails.getUser().getPassword());

            /* Authentication 객체가 리턴되면 session 영역에 저장됨 */
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    /** attemptAuthentication() 함수 실행 후 인증이 정상적으로 되었으면 실행되는 함수 */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("4. 인증 완료");

        super.successfulAuthentication(request, response, chain, authResult);
    }
}


// 1. /login 요청을 해서 username, password를 전송하면 UsernamePasswordAuthenticationFilter가 동작을 함
// 2. 하지만 현재 SecurityConfig 클래스에서 .formLogin().disable() 메서드를 통해 폼 로그인 미사용 설정을 했기 때문에 동작하지 않음
// 3. 따라서 SecurityConfig 클래스에 별도로 등록을 해주어야 함
// 4. AuthenticationManager 객체를 통해 로그인을 수행하기 때문에 AuthenticationManager 객체 또한 선을을 해야 함