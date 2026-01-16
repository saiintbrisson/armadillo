package rs.luiz.hytale.offline_mode;

import com.hypixel.hytale.server.core.auth.JWTValidator;
import com.hypixel.hytale.server.core.auth.ServerAuthManager;
import com.hypixel.hytale.server.core.auth.SessionServiceClient;
import com.hypixel.hytale.server.core.io.handlers.login.HandshakeHandler;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.lang.reflect.Field;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

public class AuthBypass {
    public static void install() throws Exception {
        installBypassJWTValidator();
        installBypassSessionServiceClient();
        installBypassServerAuthManager();
        System.out.println("[AuthBypass] All authentication checks disabled");
    }

    private static void installBypassJWTValidator() throws Exception {
        Field field = HandshakeHandler.class.getDeclaredField("jwtValidator");
        field.setAccessible(true);

        JWTValidator bypass = new JWTValidator(null, "", "") {
            @Override
            public IdentityTokenClaims validateIdentityToken(String identityToken) {
                if (identityToken == null || identityToken.isEmpty()) {
                    return null;
                }

                try {
                    SignedJWT signedJWT = SignedJWT.parse(identityToken);
                    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                    IdentityTokenClaims claims = new IdentityTokenClaims();
                    claims.issuer = claimsSet.getIssuer();
                    claims.subject = claimsSet.getSubject();
                    claims.issuedAt = claimsSet.getIssueTime() != null
                            ? claimsSet.getIssueTime().toInstant().getEpochSecond() : null;
                    claims.expiresAt = claimsSet.getExpirationTime() != null
                            ? claimsSet.getExpirationTime().toInstant().getEpochSecond() : null;
                    claims.notBefore = claimsSet.getNotBeforeTime() != null
                            ? claimsSet.getNotBeforeTime().toInstant().getEpochSecond() : null;
                    claims.scope = claimsSet.getStringClaim("scope");

                    // The original JWTValidator tries parsing from a field called username,
                    // but it's now an object with the username inside.
                    Map<String, Object> profile = claimsSet.getJSONObjectClaim("profile");
                    if (profile != null) {
                        claims.username = (String) profile.get("username");
                    }

                    System.out.println("[AuthBypass] Identity token parsed for: " + claims.username);
                    return claims;
                } catch (Exception e) {
                    System.err.println("[AuthBypass] Failed to parse identity token: " + e.getMessage());
                    return null;
                }
            }

            @Override
            public JWTClaims validateToken(String accessToken, X509Certificate clientCert) {
                if (accessToken == null || accessToken.isEmpty()) {
                    return null;
                }

                try {
                    SignedJWT signedJWT = SignedJWT.parse(accessToken);
                    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                    JWTClaims claims = new JWTClaims();
                    claims.issuer = claimsSet.getIssuer();
                    claims.audience = claimsSet.getAudience() != null && !claimsSet.getAudience().isEmpty()
                            ? claimsSet.getAudience().get(0) : null;
                    claims.subject = claimsSet.getSubject();
                    claims.username = claimsSet.getStringClaim("username");
                    claims.ipAddress = claimsSet.getStringClaim("ip");
                    claims.issuedAt = claimsSet.getIssueTime() != null
                            ? claimsSet.getIssueTime().toInstant().getEpochSecond() : null;
                    claims.expiresAt = claimsSet.getExpirationTime() != null
                            ? claimsSet.getExpirationTime().toInstant().getEpochSecond() : null;
                    claims.notBefore = claimsSet.getNotBeforeTime() != null
                            ? claimsSet.getNotBeforeTime().toInstant().getEpochSecond() : null;

                    // Extract certificate fingerprint from cnf claim (but we won't validate it)
                    Map<String, Object> cnfClaim = claimsSet.getJSONObjectClaim("cnf");
                    if (cnfClaim != null) {
                        claims.certificateFingerprint = (String) cnfClaim.get("x5t#S256");
                    }

                    System.out.println("[AuthBypass] Access token parsed for: " + claims.username);
                    return claims;
                } catch (Exception e) {
                    System.err.println("[AuthBypass] Failed to parse access token: " + e.getMessage());
                    return null;
                }
            }
        };

        field.set(null, bypass);
        System.out.println("[AuthBypass] JWTValidator bypassed (parsing without verification)");
    }

    private static void installBypassSessionServiceClient() throws Exception {
        Field field = HandshakeHandler.class.getDeclaredField("sessionServiceClient");
        field.setAccessible(true);

        SessionServiceClient bypass = new SessionServiceClient("https://sessions.hytale.com") {
            @Override
            public CompletableFuture<String> requestAuthorizationGrantAsync(
                    String identityToken, String serverAudience, String bearerToken) {
                return CompletableFuture.completedFuture("BYPASS");
            }

            @Override
            public CompletableFuture<String> exchangeAuthGrantForTokenAsync(
                    String authorizationGrant, String x509Fingerprint, String bearerToken) {
                return CompletableFuture.completedFuture("BYPASS");
            }

            @Override
            public SessionServiceClient.GameSessionResponse createGameSession(
                    String oauthAccessToken, UUID profileUuid) {
                GameSessionResponse response = new GameSessionResponse();
                response.sessionToken = "BYPASS_SESSION";
                response.identityToken = "BYPASS_IDENTITY";
                response.expiresAt = null; // Must be null to prevent auto-refresh scheduling
                System.out.println("[AuthBypass] createGameSession bypassed for profile: " + profileUuid);
                return response;
            }
        };

        field.set(null, bypass);
        System.out.println("[AuthBypass] SessionServiceClient bypassed (handshake + session creation)");
    }

    // Inject fake game session so getSessionToken()/getIdentityToken() return non-null
    @SuppressWarnings("unchecked")
    private static void installBypassServerAuthManager() throws Exception {
        ServerAuthManager manager = ServerAuthManager.getInstance();

        Field sessionField = ServerAuthManager.class.getDeclaredField("gameSession");
        sessionField.setAccessible(true);

        AtomicReference<SessionServiceClient.GameSessionResponse> sessionRef =
                (AtomicReference<SessionServiceClient.GameSessionResponse>) sessionField.get(manager);

        SessionServiceClient.GameSessionResponse fakeSession = new SessionServiceClient.GameSessionResponse();
        fakeSession.sessionToken = "BYPASS_SESSION";
        fakeSession.identityToken = "BYPASS_IDENTITY";
        fakeSession.expiresAt = null; // Must be null to prevent auto-refresh scheduling
        sessionRef.set(fakeSession);

        Field authModeField = ServerAuthManager.class.getDeclaredField("authMode");
        authModeField.setAccessible(true);
        authModeField.set(manager, ServerAuthManager.AuthMode.EXTERNAL_SESSION);

        System.out.println("[AuthBypass] ServerAuthManager bypassed");
    }
}
