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
import com.epam.digital.data.platform.starter.security.exception.JwtParsingException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Component that is used for parsing {@link JwtClaimsDto} from string JWT token
 */
@Component
@RequiredArgsConstructor
public class TokenParser {

  private final ObjectMapper objectMapper;

  /**
   * Parsing {@link JwtClaimsDto} from string JWT token
   *
   * @param token string JWT token
   * @return dto of JWT claims
   */
  public JwtClaimsDto parseClaims(String token) {
    try {
      var signedJWT = SignedJWT.parse(token);
      return objectMapper.readValue(signedJWT.getPayload().toString(), JwtClaimsDto.class);
    } catch (ParseException | JsonProcessingException e) {
      throw new JwtParsingException(e.getMessage());
    }
  }
}
