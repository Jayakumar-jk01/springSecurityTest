package com.jayakumar.springSecurityTest;

import com.jayakumar.springSecurityTest.jwt.AuthEntryPointJwt;
import com.jayakumar.springSecurityTest.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;
import static org.springframework.security.config.Customizer.withDefaults;
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
   DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unAuthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter()
    {
        return  new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/signin").permitAll()
                .anyRequest().authenticated());
//        http.formLogin(withDefaults());
        http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.httpBasic(withDefaults());
        http.exceptionHandling(exception->exception.authenticationEntryPoint(unAuthorizedHandler));
        http.headers(headers->headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
        http.csrf(csrf->csrf.disable());

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource)
    {
        return  new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService)
    {
        return args->{
            JdbcUserDetailsManager manager=(JdbcUserDetailsManager) userDetailsService;
            UserDetails user1= User.withUsername("jayakumar").
                    password(passwordEncoder().encode("jeevan2001"))
                    .roles("USER").build();
            UserDetails user2= User.withUsername("jaykar").
                    password(passwordEncoder().encode("helloworld"))
                    .roles("ADMIN").build();

            JdbcUserDetailsManager userDetailsManager=new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(user2);


        };
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {

            return  builder.getAuthenticationManager();

    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }


}
