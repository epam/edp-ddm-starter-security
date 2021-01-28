# ddm-starter-security

### Overview

* Project with configuration for authentication.

### Usage

1. Specify dependency in your service:

```xml

<dependencies>
  ...
  <dependency>
    <groupId>com.epam.digital.data.platform</groupId>
    <artifactId>ddm-starter-security</artifactId>
    <version>...</version>
  </dependency>
  ...
</dependencies>
```

2. Auto-configuration should be activated through the `@SpringBootApplication` annotation or
   using `@EnableAutoConfiguration` annotation in main class

3. Available properties are following:

* `platform.security.enabled` (`boolean|default - true`) - whether auth configuration should be
  applied or not if false then local security configuration applies

4. To enable security for spring beans use:
    * `com.epam.digital.data.platform.starter.security.annotation.PreAuthorizeAnySystemRole` -
      checks any system role (citizen / officer);
    * `com.epam.digital.data.platform.starter.security.annotation.PreAuthorizeCitizen` - checks
      citizen role;
    * `com.epam.digital.data.platform.starter.security.annotation.PreAuthorizeOfficer` - checks
      officer role.

### Test execution

* Tests could be run via maven command:
    * `mvn verify` OR using appropriate functions of your IDE.

### License

The ddm-starter-security is Open Source software released under
the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).