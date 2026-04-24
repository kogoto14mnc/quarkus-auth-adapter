package dev.aulait.qaa.api;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class RestrictedClient {

  private RestClient client;
  private String basePath;

  public String get() {
    return client.get(basePath, String.class);
  }

  public ErrorResponse getAsError() {
    return client.get(basePath, ErrorResponse.class);
  }
}
