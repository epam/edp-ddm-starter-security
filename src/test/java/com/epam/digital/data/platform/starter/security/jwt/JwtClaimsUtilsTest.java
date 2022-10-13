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

import com.epam.digital.data.platform.starter.security.dto.JwtClaimsDto;
import com.epam.digital.data.platform.starter.security.dto.enums.SubjectType;
import com.epam.digital.data.platform.starter.security.exception.JwtClaimIncorrectAttributeException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
public class JwtClaimsUtilsTest {

  private final TokenParser tokenParser = new TokenParser(new ObjectMapper());

  @SneakyThrows
  @Test
  public void shouldGetAttributesFromJwtToken() throws IOException {
    var jwt = new JwtClaimsDto();
    jwt.setDrfo("drfo");
    jwt.setEdrpou("edrpou");
    jwt.setKatottg(List.of("el1", "el2"));
    jwt.setFullName("fullname");
    jwt.setOtherClaims("claim1", "claim1");
    jwt.setOtherClaims("claim2", "claim2");

    assertThat(JwtClaimsUtils.getAttributeValue(jwt, "drfo")).isEqualTo("drfo");
    assertThatThrownBy(() -> JwtClaimsUtils.getAttributeValue(jwt, "random")).isInstanceOf(JwtClaimIncorrectAttributeException.class);
    assertThat(JwtClaimsUtils.getAttributeValue(jwt, "edrpou")).isEqualTo("edrpou");
    assertThat(JwtClaimsUtils.getAttributeValueAsStringList(jwt, "katottg")).hasSize(2);
    assertThat(JwtClaimsUtils.getAttributeValueAsStringList(jwt, "katottg").get(0)).isEqualTo("el1");
    assertThat(JwtClaimsUtils.getAttributeValue(jwt, "fullName")).isEqualTo("fullname");
    assertThat(JwtClaimsUtils.getAttributeValue(jwt, "claim1")).isEqualTo("claim1");
    assertThat(JwtClaimsUtils.getAttributeValue(jwt, "claim2")).isEqualTo("claim2");
  }
}
