package dev.aulait.qaa.qkref;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.aulait.qaa.api.DPoPAuthClient;
import dev.aulait.qaa.api.LoginResponse;
import dev.aulait.qaa.api.MeResponse;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import java.net.http.HttpResponse;
import java.util.UUID;
import org.junit.jupiter.api.Test;

@QuarkusIntegrationTest
class DPoPAuthControllerIT {

  @Test
  void login() {
    DPoPAuthClient client = new DPoPAuthClient();

    LoginResponse response = client.login(AuthDataFactory.createProvider1());

    assertNotNull(response.getAccessToken());
  }

  @Test
  void refreshToken() {
    DPoPAuthClient client = new DPoPAuthClient();

    LoginResponse loginResponse = client.login(AuthDataFactory.createProvider1());
    LoginResponse refreshResponse = client.tokenRefresh();

    assertNotEquals(loginResponse.getAccessToken(), refreshResponse.getAccessToken());
  }

  @Test
  void restrictedAccess() {
    DPoPAuthClient client = new DPoPAuthClient();
    client.login(AuthDataFactory.createProvider1());

    HttpResponse<String> response = client.getRestricted();

    assertEquals(200, response.statusCode());
    assertEquals(RestrictedController.GET_MESSAGE, response.body());
  }

  @Test
  void restrictedAccessRejectedWithoutProof() {
    DPoPAuthClient client = new DPoPAuthClient();
    client.login(AuthDataFactory.createProvider1());

    HttpResponse<String> response = client.getRestrictedWithoutProof();

    assertEquals(401, response.statusCode());
  }

  @Test
  void restrictedAccessRequiresNonce() {
    DPoPAuthClient client = new DPoPAuthClient();
    client.login(AuthDataFactory.createProvider1());

    // First request without nonce — RS should return 401 with DPoP-Nonce
    HttpResponse<String> response = client.getRestrictedWithoutNonceAndRetry();

    assertEquals(401, response.statusCode());

    String wwwAuth = response.headers().firstValue("WWW-Authenticate").orElse("");
    assertTrue(wwwAuth.contains("use_dpop_nonce"), "Expected use_dpop_nonce error");

    String nonce = response.headers().firstValue("DPoP-Nonce").orElse(null);
    assertNotNull(nonce, "Expected DPoP-Nonce header");

    // Retry with nonce
    HttpResponse<String> retryResponse = client.getRestrictedWithNonce(nonce);
    assertEquals(200, retryResponse.statusCode());
    assertEquals(RestrictedController.GET_MESSAGE, retryResponse.body());
  }

  @Test
  void loginInvalidCredentials() {
    DPoPAuthClient client = new DPoPAuthClient();

    HttpResponse<String> response =
        client.loginWithRawResponse(AuthDataFactory.createNonExistentUser());

    assertEquals(400, response.statusCode());
  }

  @Test
  void meAuthenticated() {
    DPoPAuthClient client = new DPoPAuthClient();
    client.login(AuthDataFactory.createProvider1());

    MeResponse me = client.me();

    assertEquals("ProviderFirstName", me.getFirstName());
    assertEquals("ProviderLastName", me.getLastName());
    assertTrue(me.getRoles().contains("provider"));
  }

  @Test
  void meUnauthenticated() {
    DPoPAuthClient unauthenticatedClient = new DPoPAuthClient();

    MeResponse me = unauthenticatedClient.me();

    assertNull(me.getFirstName());
    assertNull(me.getLastName());
    assertNull(me.getRoles());
  }

  @Test
  void dpopJtiReplayRejected() {
    DPoPAuthClient client = new DPoPAuthClient();
    client.login(AuthDataFactory.createProvider1());

    String fixedJti = UUID.randomUUID().toString();

    // First request with this jti should succeed
    HttpResponse<String> first = client.getRestrictedWithFixedJti(fixedJti);
    assertEquals(200, first.statusCode());

    // Second request with the same jti should be rejected as replay
    HttpResponse<String> second = client.getRestrictedWithFixedJti(fixedJti);
    assertEquals(401, second.statusCode());

    String wwwAuth = second.headers().firstValue("WWW-Authenticate").orElse("");
    assertTrue(wwwAuth.contains("invalid_dpop_proof"), "Expected invalid_dpop_proof error");
  }

  @Test
  void dpopDifferentJtiAccepted() {
    DPoPAuthClient client = new DPoPAuthClient();
    client.login(AuthDataFactory.createProvider1());

    // Two requests with different jti values should both succeed
    HttpResponse<String> first = client.getRestrictedWithFixedJti(UUID.randomUUID().toString());
    assertEquals(200, first.statusCode());

    HttpResponse<String> second = client.getRestrictedWithFixedJti(UUID.randomUUID().toString());
    assertEquals(200, second.statusCode());
  }
}
