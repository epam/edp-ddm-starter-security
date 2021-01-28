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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class TokenProviderTest {

  private final TokenProvider tokenProvider = new TokenProvider(
      new TokenParser(new ObjectMapper()));

  @Test
  public void shouldCreateAuthenticationBasedOnJwtToken() throws IOException {
    var token = new String(ByteStreams.toByteArray(
        TokenProviderTest.class.getResourceAsStream("/json/officerAccessToken.json")));

    var authentication = tokenProvider.getAuthentication(token);

    assertThat(authentication).isNotNull();
    assertThat(authentication.getName()).isEqualTo("testuser");
    assertThat(authentication.getAuthorities()).isNotEmpty();
    var authorities = authentication.getAuthorities();
    assertThat(authorities.stream().anyMatch(a -> "officer".equals(a.getAuthority()))).isTrue();
  }

  @Test
  public void shouldCreateAuthenticationWithoutAuthorities() throws IOException {
    var token = new String(ByteStreams.toByteArray(
        TokenProviderTest.class.getResourceAsStream("/json/simpleAccessToken.json")));

    var authentication = tokenProvider.getAuthentication(token);

    assertThat(authentication.getAuthorities()).isEmpty();
  }
}