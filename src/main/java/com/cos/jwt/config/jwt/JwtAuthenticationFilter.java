package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
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
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

//스프링시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// /login을 요청해서 username,password 전송하면 (post)
//UsernamePasswordAuthenticationFilter 동작을 함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    
    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");

        //1. username, password 받아서
        try {
            //Form형식으로 올경우
//            BufferedReader br =request.getReader();
//
//            String input = null;
//            while((input=br.readLine())!=null){
//                System.out.println(input); //username과 password가 나온다.
//            }

            //JSON형식일 경우
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()); //토큰 생성

            //2. 정상인지 로그인 시도를 해보는 것. authenticationManager로 로그인 시도를 하면!!
            Authentication authentication = authenticationManager.authenticate(authenticationToken); //토큰을 날려줌.
            //PrincipalDetailsService의 loadUserByUsername()함수가 실행됨. 함수가 실행된 후 정상이면 authentication 리턴됨.
            //authentication에는 내가 로그인한 정보가 담긴다.
            //authentication은 토큰을 통해 만들어짐.
            //authentication이 정상적으로 만들어지면 가지고 있는다.
            //DB에 있는 username과 password가 일치한다는 뜻임. 인증이 끝임.

            //3. PrincipalDetails를 세션에 담고 * 세션에 담지 않으면 antMatchers 권한관리를 하기위해서 권한 관리가 필요없으면 세션에 담지 않아도 된다.
            //=> authentication 객체가 session에 저장됨. 로그인이 되었다는 뜻
            PrincipalDetails principalDetails=(PrincipalDetails)authentication.getPrincipal();
            //authentication.getPrincipal()가 오브젝트로 리턴하기 때문에 다운캐스팅을해줘야함.

            System.out.println("로그인 완료됨: "+principalDetails.getUser().getUsername());//이 코드가 잘 찍혔다면 로그인이 되었다는 뜻임.
            //4. JWT 토큰을 만들어서 응답해주면 됨.
            return authentication; //authentication 객체가 session영역에 저장을 해야하는데 return이 그방법임 즉 세션에 저장됨.
            //return 의 이유는 권한 관리를 security가 대신해주기 때문에 편하려고 만드는 것임.
            //굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한처리때문에 session에 넣어준다.

//            System.out.println(request.getInputStream().toString());
        } catch (IOException e) {
//            throw new RuntimeException(e);
            e.printStackTrace();
        }




        return null;
    }

    //attemptAuthnentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨.
    //JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {


        System.out.println("successfulAuthentication 실행됨: 이늦ㅇ이 완료되었다는 뜻임.");
        PrincipalDetails principalDetails=(PrincipalDetails)authResult.getPrincipal();


        //RSA방식은 아니고 Hash암호방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰") //크게 의미없음.
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))//현재시간 + 60000*10 = 10분
                .withClaim("id",principalDetails.getUser().getUsername()) //witClaim은 비공개 클레임인데 넣고싶은 키벨류를 막넣으면됨.
                .withClaim("username",principalDetails.getUser().getUsername()) //ID와 username정도만 토큰에 담아준다.
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); //시크릿값을 가지고 있어야함.

        response.addHeader("Authorization","Bearer "+jwtToken);



        super.successfulAuthentication(request, response, chain, authResult);
    }
}


