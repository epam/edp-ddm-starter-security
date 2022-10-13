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
import com.epam.digital.data.platform.starter.security.exception.JwtClaimIncorrectAttributeException;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class JwtClaimsUtils {

  public static final String JWT_CLAIMS_FIXED_ATTRIBUTE_KATOTTG = "katottg";
  public static final String JWT_CLAIMS_FIXED_ATTRIBUTE_EDRPOY = "edrpou";
  public static final String JWT_CLAIMS_FIXED_ATTRIBUTE_DRFO = "drfo";
  public static final String JWT_CLAIMS_FIXED_ATTRIBUTE_FULL_NAME = "fullName";

  public static final Set<String> JWT_CLAIMS_FIXED_ATTRIBUTES = Set.of(JWT_CLAIMS_FIXED_ATTRIBUTE_DRFO,
          JWT_CLAIMS_FIXED_ATTRIBUTE_EDRPOY, JWT_CLAIMS_FIXED_ATTRIBUTE_KATOTTG,
          JWT_CLAIMS_FIXED_ATTRIBUTE_FULL_NAME);

  private static final Map<String, Function<JwtClaimsDto, Object>> JWT_KNOWN_ATTRS_MAPPING = Map.of(
          JWT_CLAIMS_FIXED_ATTRIBUTE_DRFO, JwtClaimsDto::getDrfo,
          JWT_CLAIMS_FIXED_ATTRIBUTE_EDRPOY, JwtClaimsDto::getEdrpou,
          JWT_CLAIMS_FIXED_ATTRIBUTE_KATOTTG, JwtClaimsDto::getKatottg,
          JWT_CLAIMS_FIXED_ATTRIBUTE_FULL_NAME, JwtClaimsDto::getFullName

  );

  public static boolean isAttributeExists(JwtClaimsDto dto, String attribute) {
    if (JWT_CLAIMS_FIXED_ATTRIBUTES.contains(attribute)) {
      return true;
    }

    return dto.getOtherClaims().containsKey(attribute);
  }

  public static Object getAttributeValue(JwtClaimsDto dto, String attribute) throws JwtClaimIncorrectAttributeException {
    if (JWT_CLAIMS_FIXED_ATTRIBUTES.contains(attribute)) {
      return JWT_KNOWN_ATTRS_MAPPING.get(attribute).apply(dto);
    }

    if (!dto.getOtherClaims().containsKey(attribute)) {
      throw new JwtClaimIncorrectAttributeException("Attribute not found: " + attribute);
    }

    return dto.getOtherClaims().get(attribute);
  }

  public static List<String> getAttributeValueAsStringList(JwtClaimsDto dto, String attribute) throws JwtClaimIncorrectAttributeException {
    var res = getAttributeValue(dto, attribute);
    if (res == null) {
      return new ArrayList<>();
    }
    if (res instanceof Collection) {
      return ((Collection<?>) res).stream().filter(Objects::nonNull).map(String::valueOf).collect(Collectors.toList());
    }
    return Collections.singletonList(String.valueOf(res));
  }
}
