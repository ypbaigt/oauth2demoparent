package com.bai.core.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class MyResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    protected AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    protected AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.formLogin()
                .loginProcessingUrl("/form/token")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler);

        httpSecurity.authorizeRequests()
                .antMatchers(
                        "register"
                )
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .csrf()
                .disable();
    }

}
