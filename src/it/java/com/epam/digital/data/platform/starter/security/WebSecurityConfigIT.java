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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.epam.digital.data.platform.starter.security.annotation.PreAuthorizeAnySystemRole;
import com.epam.digital.data.platform.starter.security.annotation.PreAuthorizeCitizen;
import com.epam.digital.data.platform.starter.security.annotation.PreAuthorizeOfficer;
import com.epam.digital.data.platform.starter.security.dto.ErrorRestResponseDto;
import com.epam.digital.data.platform.starter.security.jwt.JwtAuthenticationFilter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@SpringBootTest(classes = {WebSecurityConfigIT.TestConfiguration.class})
@EnableConfigurationProperties(ServerProperties.class)
public class WebSecurityConfigIT {

  @Autowired
  private MockMvc mockMvc;
  @Autowired
  private ObjectMapper objectMapper;

  @Test
  public void shouldReturn200() {
    var token = readToken("/json/simpleAccessToken.json");
    var responseBody = performRequestAndExpectStatusAndReturn("/test", token, 200);
    assertThat(responseBody).isNotNull().isEqualTo("test");
  }

  @Test
  public void shouldAuthorizeOfficerSuccessfully() {
    var token = readToken("/json/officerAccessToken.json");
    var responseBody = performRequestAndExpectStatusAndReturn("/pre-authorized-path-officer", token,
        200);
    assertThat(responseBody).isNotNull().isEqualTo("officer");
  }

  @Test
  public void shouldAuthorizeCitizenSuccessfully() {
    var token = readToken("/json/citizenAccessToken.json");
    var responseBody = performRequestAndExpectStatusAndReturn("/pre-authorized-path-citizen", token,
        200);
    assertThat(responseBody).isNotNull().isEqualTo("citizen");
  }

  @Test
  public void shouldAuthorizeAllSuccessfully() {
    var responses = List.of("/json/officerAccessToken.json", "/json/citizenAccessToken.json")
        .stream().map(this::readToken)
        .map(token -> performRequestAndExpectStatusAndReturn("/pre-authorized-path-all", token,
            200))
        .collect(Collectors.toList());

    assertThat(responses).hasSize(2).contains("all");
  }

  @Test
  public void shouldReturn403() throws JsonProcessingException {
    var token = readToken("/json/simpleAccessToken.json");

    var responseBody = performRequestAndExpectStatusAndReturn("/pre-authorized-path-officer", token,
        403);

    assertThat(responseBody).isNotNull();
    var errorRestResponseDto = objectMapper.readValue(responseBody, ErrorRestResponseDto.class);
    assertThat(errorRestResponseDto.getError().getCode()).isEqualTo("403");
    assertThat(errorRestResponseDto.getError().getMessage()).isEqualTo("Access is denied");
  }

  @Test
  public void shouldReturn401() throws Exception {
    String responseBody = mockMvc.perform(MockMvcRequestBuilders.get("/test"))
        .andExpect(status().is(401)).andReturn().getResponse().getContentAsString();

    assertThat(responseBody).isNotNull();
    ErrorRestResponseDto errorRestResponseDto = objectMapper
        .readValue(responseBody, ErrorRestResponseDto.class);
    assertThat(errorRestResponseDto.getError().getCode()).isEqualTo("401");
    assertThat(errorRestResponseDto.getError().getMessage()).isEqualTo("Unauthorized");
  }

  private String readToken(String tokenPath) {
    try {
      return new String(
          ByteStreams.toByteArray(WebSecurityConfigIT.class.getResourceAsStream(tokenPath)));
    } catch (IOException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private String performRequestAndExpectStatusAndReturn(String urlTemplate, String token,
      int expectedStatus) {
    try {
      return mockMvc.perform(MockMvcRequestBuilders.get(urlTemplate)
          .header(JwtAuthenticationFilter.AUTHORIZATION_HEADER, token))
          .andExpect(status().is(expectedStatus)).andReturn().getResponse().getContentAsString();
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  @Configuration
  @Import({MockMvcAutoConfiguration.class, JacksonAutoConfiguration.class})
  protected static class TestConfiguration {

    @RestController
    protected static class TestController {

      @GetMapping("/test")
      public String test() {
        return "test";
      }

      @GetMapping("/pre-authorized-path-officer")
      @PreAuthorizeOfficer
      public String testOfficerAuthority() {
        return "officer";
      }

      @GetMapping("/pre-authorized-path-citizen")
      @PreAuthorizeCitizen
      public String testCitizenAuthority() {
        return "citizen";
      }

      @GetMapping("/pre-authorized-path-all")
      @PreAuthorizeAnySystemRole
      public String testAllAuthority() {
        return "all";
      }
    }
  }
}