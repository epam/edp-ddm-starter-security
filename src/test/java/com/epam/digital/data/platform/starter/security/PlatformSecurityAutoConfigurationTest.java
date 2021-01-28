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

package com.epam.digital.data.platform.starter.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.epam.digital.data.platform.starter.security.jwt.JwtAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

public class PlatformSecurityAutoConfigurationTest {

  private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
      .withBean(ObjectMapper.class)
      .withConfiguration(AutoConfigurations.of(PermitAllSecurityAutoConfiguration.class,
          PlatformSecurityAutoConfiguration.class));

  @Test
  public void shouldLoadPlatformSecurityAutoConfiguration() {
    contextRunner.run(context -> {
      assertThat(context).hasSingleBean(PlatformSecurityAutoConfiguration.class);
      assertThat(context).doesNotHaveBean(PermitAllSecurityAutoConfiguration.class);
      assertThat(context).hasSingleBean(WebSecurityConfig.class);
      assertThat(context).hasSingleBean(JwtAuthenticationFilter.class);
    });
  }

  @Test
  public void shouldLoadPermitAllSecurityAutoConfiguration() {
    contextRunner.withPropertyValues(
        "platform.security.enabled=false"
    )
    .run(context -> {
      assertThat(context).hasSingleBean(PermitAllSecurityAutoConfiguration.class);
      assertThat(context).doesNotHaveBean(PlatformSecurityAutoConfiguration.class);
      assertThat(context).hasSingleBean(PermitAllWebSecurityConfig.class);
      assertThat(context.getEnvironment().getProperty("platform.security.enabled")).isEqualTo("false");
    });
  }

}