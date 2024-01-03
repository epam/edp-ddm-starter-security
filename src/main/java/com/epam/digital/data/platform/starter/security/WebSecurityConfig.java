/*
 * Copyright 2021 EPAM Systems.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.epam.digital.data.platform.starter.security;

import com.epam.digital.data.platform.starter.security.config.Whitelist;
import com.epam.digital.data.platform.starter.security.jwt.JwtConfigurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Order(WebSecurityConfig.DEFAULT_ORDER)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig {

  public static final int DEFAULT_ORDER = Ordered.HIGHEST_PRECEDENCE + 10;

  private final JwtConfigurer securityConfigurerAdapter;
  private final AccessDeniedHandler accessDeniedHandler;
  private final AuthenticationEntryPoint authenticationErrorHandler;
  private final Whitelist whitelist;

  private final boolean csrfEnabled;

  public WebSecurityConfig(
          JwtConfigurer securityConfigurerAdapter,
          AccessDeniedHandler accessDeniedHandler,
          AuthenticationEntryPoint authenticationErrorHandler,
          Whitelist whitelist,
          @Value("${platform.security.csrf.enabled:false}") boolean csrfEnabled) {
    this.securityConfigurerAdapter = securityConfigurerAdapter;
    this.accessDeniedHandler = accessDeniedHandler;
    this.authenticationErrorHandler = authenticationErrorHandler;
    this.whitelist = whitelist;
    this.csrfEnabled = csrfEnabled;
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().requestMatchers(whitelist.getRequestMatcher());
  }
  @Bean
  public SecurityFilterChain generalFilterChain(HttpSecurity http) throws Exception {

    if (csrfEnabled) {
      CsrfTokenRequestAttributeHandler delegate = new CsrfTokenRequestAttributeHandler();
      delegate.setCsrfRequestAttributeName(null);
      http.csrf(crf -> crf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(delegate));
    } else {
      http.csrf(AbstractHttpConfigurer::disable);
    }
    http.
            exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationErrorHandler).accessDeniedHandler(accessDeniedHandler)).
            sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).
            authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).with(securityConfigurerAdapter, Customizer.withDefaults());
    return http.build();
  }
  @Bean
  public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
    return new InMemoryUserDetailsManager();
  }


}
