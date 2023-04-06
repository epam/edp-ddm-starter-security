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
  @Deprecated(forRemoval = true)
  @JsonProperty("KATOTTG")
  private List<String> katottg;

  public void setEdrpou(Object edrpou) {
    this.edrpou = objectToString(edrpou);
  }

  public void setDrfo(Object drfo) {
    this.drfo = objectToString(drfo);
  }

  public void setFullName(Object fullName) {
    this.fullName = objectToString(fullName);
  }

  public void setSubjectType(Object subjectType) {
    this.subjectType = SubjectType.valueOf(objectToString(subjectType));
  }

  public void setRepresentative(Object representative) {
    if (List.class.isInstance(representative)) {
      this.representative = Boolean.parseBoolean(((List<String>) representative).get(0));
    } else if (Boolean.class.isInstance(representative)) {
      this.representative = (Boolean) representative;
    } else {
      this.representative = false;
    }
  }

  private String objectToString(Object attribute) {
    if (List.class.isInstance(attribute)) {
      return ((List<String>) attribute).get(0);
    } else if (String.class.isInstance(attribute)) {
      return (String) attribute;
    }
    return "";
  }
}
