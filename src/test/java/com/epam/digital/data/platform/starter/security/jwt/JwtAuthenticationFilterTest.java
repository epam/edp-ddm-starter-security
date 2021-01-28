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

package com.epam.digital.data.platform.starter.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.epam.digital.data.platform.starter.security.config.Whitelist;
import java.io.IOException;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

@ExtendWith(MockitoExtension.class)
public class JwtAuthenticationFilterTest {

  @Mock
  private HttpServletRequest httpServletRequest;
  @Mock
  private HttpServletResponse httpServletResponse;
  @Mock
  private FilterChain filterChain;

  @Mock
  private TokenProvider tokenProvider;

  @Mock
  private Whitelist whitelist;

  private JwtAuthenticationFilter filter;

  @BeforeEach
  public void init() {
    filter = new JwtAuthenticationFilter(tokenProvider, whitelist);
  }

  @AfterEach
  public void tearDown() {
    SecurityContextHolder.getContext().setAuthentication(null);
  }

  @Test
  public void shouldSetAuthentication() throws ServletException, IOException {
    when(httpServletRequest.getHeader(JwtAuthenticationFilter.AUTHORIZATION_HEADER))
        .thenReturn("token");
    User principal = new User("username", "", Collections.emptyList());
    Authentication auth = new UsernamePasswordAuthenticationToken(principal,
        "token", Collections.emptyList());
    when(tokenProvider.getAuthentication("token")).thenReturn(auth);

    filter.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThat(authentication).isNotNull();
    assertThat(authentication.getName()).isEqualTo("username");
  }

  @Test
  public void shouldNotSetAuthentication() throws ServletException, IOException {
    filter.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThat(authentication).isNull();
  }
}