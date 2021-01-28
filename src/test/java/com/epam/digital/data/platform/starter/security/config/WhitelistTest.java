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

import static com.epam.digital.data.platform.starter.security.config.Whitelist.DEFAULT_AUTH_WHITELIST;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;

class WhitelistTest {

  SecurityProperties props = new SecurityProperties();

  @Test
  void shouldAcceptDefaultWhitelist() {
    props.setWhitelist(emptyList());
    var wl = new Whitelist(props);

    var matchers = extractMatchers(wl);

    assertThat(matchers).hasSize(DEFAULT_AUTH_WHITELIST.length);
  }

  @Test
  void shouldAcceptCustomWhitelistWhenGiven() {
    props.setWhitelist(singletonList("/openapi"));
    var wl = new Whitelist(props);

    var matchers = extractMatchers(wl);

    assertThat(matchers).hasSize(1);
  }

  @SuppressWarnings("unchecked")
  private List<RequestMatcher> extractMatchers(Whitelist wl) {
    return (List<RequestMatcher>) ReflectionTestUtils
        .getField(wl.getRequestMatcher(), "requestMatchers");
  }
}
