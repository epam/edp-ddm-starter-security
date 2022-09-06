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

package com.epam.digital.data.platform.starter.security.dto;

import com.epam.digital.data.platform.starter.security.dto.enums.SubjectType;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.keycloak.representations.IDToken;

/**
 * Dto that represents JWT claim set
 */
@Data
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class JwtClaimsDto extends IDToken {

  @JsonProperty("allowed-origins")
  private List<String> allowedOrigins;
  @JsonProperty("realm_access")
  private RolesDto realmAccess;
  @JsonProperty("resource_access")
  private Map<String, RolesDto> resourceAccess;
  private String scope;
  private List<String> roles;

  private String edrpou;
  private String drfo;
  private String fullName;
  private SubjectType subjectType;
  private boolean representative;
  @JsonProperty("KATOTTG")
  private List<String> katottg;
}
