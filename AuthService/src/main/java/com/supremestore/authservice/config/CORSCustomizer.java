package com.supremestore.authservice.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Component
public class CORSCustomizer {
    public void corsCustomizer(HttpSecurity http) throws Exception{
        http.cors(c->{
            CorsConfigurationSource source=s->{
                CorsConfiguration cc=new CorsConfiguration();
                cc.setAllowCredentials(true);
             //   cc.setAllowedOrigins(List.of("http://127.0.0.1:3000"));
                cc.setAllowedOrigins(List.of("http://127.0.0.1:8083"));
               // cc.setAllowedOrigins(List.of("localhost:3000"));
                cc.setAllowedHeaders(List.of("*"));
                cc.setAllowedMethods(List.of("*"));
              // cc.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                return  cc;
            };
            c.configurationSource(source);
        });
    }
}
