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

import com.epam.digital.data.platform.starter.security.config.SecurityProperties;
import com.epam.digital.data.platform.starter.security.config.Whitelist;
import com.epam.digital.data.platform.starter.security.jwt.DefaultAccessDeniedHandler;
import com.epam.digital.data.platform.starter.security.jwt.JwtConfigurer;
import com.epam.digital.data.platform.starter.security.jwt.DefaultAuthenticationEntryPoint;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@Import({WebSecurityConfig.class})
@EnableConfigurationProperties(SecurityProperties.class)
@ComponentScan(basePackageClasses = {JwtConfigurer.class, Whitelist.class})
@ConditionalOnProperty(prefix = "platform.security", name = "enabled", matchIfMissing = true)
@RequiredArgsConstructor
public class PlatformSecurityAutoConfiguration {

  private final ObjectMapper objectMapper;

  @Bean
  @ConditionalOnMissingBean
  public AuthenticationEntryPoint authenticationEntryPoint() {
    return new DefaultAuthenticationEntryPoint(objectMapper);
  }

  @Bean
  @ConditionalOnMissingBean
  public AccessDeniedHandler accessDeniedHandler() {
    return new DefaultAccessDeniedHandler(objectMapper);
  }
}
