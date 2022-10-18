package com.supremestore.userresources.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import java.util.List;

@Configuration
@EnableWebSecurity


public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {

        http.cors(c->{
            CorsConfigurationSource source=s->{
                CorsConfiguration cc=new CorsConfiguration();
                cc.setAllowCredentials(true);
                cc.setAllowedOrigins(List.of("http://127.0.0.1:3000","http://127.0.0.1:8083"));
                cc.setAllowedHeaders(List.of("*"));
                cc.setAllowedMethods(List.of("*"));
                return  cc;
            };
            c.configurationSource(source);
        });

        return http.oauth2ResourceServer(j->j.jwt().jwkSetUri("http://localhost:8080/oauth2/jwks"))
                .csrf()
                .disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .build();

    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.mvcMatcher("/**")
                .authorizeRequests()
                .mvcMatchers("/**")
                .access("hasAuthority('read')")
                .and()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }

//    @Bean
//    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) throws Exception {
//        http
//                .authorizeExchange()
//                .pathMatchers("/v1/api/user/*").hasAuthority("read")
//                .anyExchange().authenticated()
//                .and()
//                .oauth2ResourceServer()
//                .jwt();
//        return http.build();
//    }
}
