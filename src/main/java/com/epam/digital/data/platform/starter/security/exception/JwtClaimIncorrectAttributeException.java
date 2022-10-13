package com.epam.digital.data.platform.starter.security.exception;

public class JwtClaimIncorrectAttributeException extends Exception {

  public JwtClaimIncorrectAttributeException(String message) {
    super(message);
  }
}
