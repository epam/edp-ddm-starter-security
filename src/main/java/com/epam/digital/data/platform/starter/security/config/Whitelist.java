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

package com.epam.digital.data.platform.starter.security.config;

import static java.util.stream.Collectors.toList;
import static org.springframework.util.CollectionUtils.isEmpty;

import java.util.Arrays;
import java.util.List;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

@Component
public class Whitelist {

  static final String[] DEFAULT_AUTH_WHITELIST = {
      "/swagger",
      "/v3/api-docs/**",
      "/swagger-ui/**",
      "/actuator/**"
  };

  private final RequestMatcher requestMatcher;

  public Whitelist(SecurityProperties properties) {
    List<RequestMatcher> matchers;
    if (isEmpty(properties.getWhitelist())) {
      matchers = Arrays.stream(DEFAULT_AUTH_WHITELIST)
          .map(AntPathRequestMatcher::new).collect(toList());
    } else {
      matchers = properties.getWhitelist().stream()
          .map(AntPathRequestMatcher::new).collect(toList());
    }
    requestMatcher = new OrRequestMatcher(matchers);
  }

  public RequestMatcher getRequestMatcher() {
    return requestMatcher;
  }
}
