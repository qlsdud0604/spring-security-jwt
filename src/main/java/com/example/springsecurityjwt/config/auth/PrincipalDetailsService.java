package com.example.springsecurityjwt.config.auth;

import com.example.springsecurityjwt.model.User;
import com.example.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        System.out.println("PrincipalDetailsService 실행");

        User userEntity = userRepository.findByUsername(username);

        return new PrincipalDetails(userEntity);
    }
}

// 1. /login 요청 시 loadUserDetailsService의 loadUserByUsername( ) 메서드가 자동으로 실행됨
// 2. 하지만 현재 SecurityConfig 클래스에서 .formLogin().disable() 메서드를 통해 폼 로그인 미사용 설정을 했기 때문에 메서드가 호출되지 않음
// 3. 따라서, 별도로 설정을 해주어야 한다. -> JwtAuthenticationFilter 클래스를 생성함으로써 해결