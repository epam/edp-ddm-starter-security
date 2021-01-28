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

package com.epam.digital.data.platform.starter.security.dto.enums;

import java.util.Arrays;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Enumeration of keycloak platform roles
 */
@AllArgsConstructor
@Getter
public enum KeycloakPlatformRole {

  OFFLINE_ACCESS("offline_access"),       // default keycloak role, will be removed
  UMA_AUTHORIZATION("uma_authorization"), // default keycloak role, will be removed
  CITIZEN("citizen"),
  ENTREPRENEUR("entrepreneur"),
  INDIVIDUAL("individual"),
  LEGAL("legal"),
  UNREGISTERED_ENTREPRENEUR("unregistered-entrepreneur"),
  UNREGISTERED_INDIVIDUAL("unregistered-individual"),
  UNREGISTERED_LEGAL("unregistered-legal");

  private final String name;

  public static boolean containsRole(String roleName) {
    return Arrays.stream(values()).anyMatch(role -> role.getName().equals(roleName));
  }
}
