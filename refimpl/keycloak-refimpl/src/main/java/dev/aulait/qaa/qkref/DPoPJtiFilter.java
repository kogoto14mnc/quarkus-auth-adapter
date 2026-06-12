package dev.aulait.qaa.qkref;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 1)
public class DPoPJtiFilter implements ContainerRequestFilter {

  @ConfigProperty(name = "qaa.dpop.nonce-ttl-seconds")
  long nonceTtlSeconds;

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private Cache<String, String> usedJtis;

  @PostConstruct
  void init() {
    usedJtis = Caffeine.newBuilder()
        .expireAfterWrite(nonceTtlSeconds, TimeUnit.SECONDS)
        .build();
  }

  @Override
  public void filter(ContainerRequestContext requestContext) {
    String dpopHeader = requestContext.getHeaderString("DPoP");
    if (dpopHeader == null) {
      return;
    }

    String jti = extractJti(dpopHeader);
    if (jti == null) {
      return;
    }

    String jtiHash = hashJti(jti);
    if (usedJtis.getIfPresent(jtiHash) != null) {
      requestContext.abortWith(
          Response.status(Response.Status.UNAUTHORIZED)
              .header("WWW-Authenticate",
                  "DPoP error=\"invalid_dpop_proof\", error_description=\"DPoP proof replay detected\"")
              .build());
      return;
    }
    usedJtis.put(jtiHash, "used");
  }

  private String extractJti(String dpopJwt) {
    String[] parts = dpopJwt.split("\\.");
    if (parts.length < 2) {
      return null;
    }
    try {
      byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
      JsonNode payload = MAPPER.readTree(payloadBytes);
      JsonNode jtiNode = payload.get("jti");
      if (jtiNode == null || !jtiNode.isTextual()) {
        return null;
      }
      return jtiNode.asText();
    } catch (Exception e) {
      return null;
    }
  }

  private String hashJti(String jti) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(jti.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 not available", e);
    }
  }
}
