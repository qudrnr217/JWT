package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration //IoC할 수 있게해줌
@EnableWebSecurity //Security 활성화
@RequiredArgsConstructor
public class SecurityConfig{

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        http.addFilterBefore(new MyFilter3(), WebAsyncManagerIntegrationFilter.class); //spring security filter chain의 BasicAuthenticationFilter 필터 전에 넣으라는 뜻임. 일반 필터이기때문에 security filter랑 같이 안되기 때문에
        //FilterConfig에 등록한것보다 무조건 security filter가 먼저 실행됨. after를 하더라도
        //JWT설정은 security filter이전에 실행되어야 하므로 before을 사용
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 사용하지 않겠다는 뜻임.
                .and()
                .addFilter(corsFilter) //Cors 필터를 넣어줌. @CrossOrigin (인증X), 시큐리티 필터에 등록인증(O)
                .formLogin().disable() //form tag로그인 방식도 안쓴다.
                .httpBasic().disable() //httpBasic은 headers에 Authorization: ID,PW를 담아서 요청하는 방식이어서 확장성은 좋지만 PW가 노출이 되기 때문에중간에 노출이 될 수 있음. 노출이 안되게하려면
                //https 서버를 써야하는데 https를 사용하면 id,pw가 암호화 돼서 날라간다. 우리가 쓸 방법은 Authorization에 token을 넣어 사용할 예정 토큰은 노출이되어도 괜춘.
                .addFilter(new JwtAuthenticationFilter(authenticationManager)) //AuthenticationManager
                .addFilter(new JwtAuthorizationFilter(authenticationManager,userRepository))
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasAnyRole('ROLE_USER','ROLE_MANAGER','ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasAnyRole('ROLE_ADMIN')")
                .anyRequest().permitAll(); //다른 요청은 막자!


        return http.build();


    }
}
