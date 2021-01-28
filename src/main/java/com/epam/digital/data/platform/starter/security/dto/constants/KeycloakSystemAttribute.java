package com.epam.digital.data.platform.starter.security.dto.constants;

/**
 * Class that represents list of keycloak system attribute constants.
 */
public final class KeycloakSystemAttribute {

  /**
   * Full name attribute that will be obtained from the keycloak user representation attribute map.
   */
  public static final String FULL_NAME_ATTRIBUTE = "fullName";

  /**
   * Index of the fullName attribute value in the attribute value list.
   */
  public static final int FULL_NAME_ATTRIBUTE_INDEX = 0;

  private KeycloakSystemAttribute() {
  }
}
