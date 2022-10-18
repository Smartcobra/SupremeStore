package com.supremestore.edgeservice.config;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;


@Configuration
@EnableWebFluxSecurity
public class Oauth2ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt();
    }
}
