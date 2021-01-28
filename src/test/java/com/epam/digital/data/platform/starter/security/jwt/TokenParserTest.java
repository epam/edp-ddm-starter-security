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

import com.epam.digital.data.platform.starter.security.dto.enums.SubjectType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class TokenParserTest {

  private final TokenParser tokenParser = new TokenParser(new ObjectMapper());

  @Test
  public void shouldGetUserAttributesFromJwtToken() throws IOException {
    var token = new String(ByteStreams.toByteArray(
        TokenProviderTest.class.getResourceAsStream("/json/officerAccessToken.json")));

    var jwtClaimsDto = tokenParser.parseClaims(token);

    assertThat(jwtClaimsDto).isNotNull();
    assertThat(jwtClaimsDto.isRepresentative()).isTrue();
    assertThat(jwtClaimsDto.getSubjectType()).isEqualTo(SubjectType.INDIVIDUAL);
  }
}
