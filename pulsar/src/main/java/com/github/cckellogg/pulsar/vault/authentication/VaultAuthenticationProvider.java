package com.github.cckellogg.pulsar.vault.authentication;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.json.JsonValue;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestResponse;

import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;

import com.github.benmanes.caffeine.cache.Expiry;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataCommand;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationProvider;
import org.apache.pulsar.broker.authentication.AuthenticationState;
import org.apache.pulsar.common.api.AuthData;

import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;

public class VaultAuthenticationProvider implements AuthenticationProvider {
    private static final Logger Log =
            Logger.getLogger(VaultAuthenticationProvider.class.getName());

    private static final long TIMEOUT_SECONDS = 10;
    private static final int THREAD_COUNT = 4;

    private static final String HTTP_HEADER_NAME = "Authorization";
    private static final String HTTP_HEADER_VALUE_PREFIX = "Bearer ";

    private static final String DEFAULT_VAULT_ADDR = "http://127.0.0.1:8200";
    private static final String DEFAULT_VAULT_LOOKUP_PATH = "/v1/auth/token/lookup-self";
    // The token is set directly as a header for the HTTP API.
    // The header should be either X-Vault-Token: <token> or Authorization: Bearer <token>
    private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
    private static final String VAULT_ADDR_ENV_VAR = "VAULT_ADDR";

    private static final int TOKEN_TTL_SECONDS = 300; // 5 mins
    private static final int TOKEN_TTL_RANGE_SECONDS = 300; // 5 mins

    private final ExecutorService executorService =
            Executors.newScheduledThreadPool(THREAD_COUNT,
                    DefaultThreadFactory.create("auth-executor"));

    private AsyncLoadingCache<String, String> tokenCache = Caffeine.newBuilder()
            .executor(executorService)
            .expireAfter(new RandomExpiry(TOKEN_TTL_SECONDS, TOKEN_TTL_RANGE_SECONDS))
            .buildAsync((key, executor1) -> null);;

    @Override
    public void initialize(ServiceConfiguration serviceConfiguration) throws IOException {
    }

    private String vaultAddress() {
        final String vaultAddr = System.getenv(VAULT_ADDR_ENV_VAR);
        if (isEmpty(vaultAddr)) {
            return DEFAULT_VAULT_ADDR;
        }

        return vaultAddr.trim();
    }

    @Override
    public String authenticate(AuthenticationDataSource authenticationDataSource)
            throws AuthenticationException {
        final String token = tokenFromSource(authenticationDataSource);
        if (isEmpty(token)) {
            throw new AuthenticationException("missing client token");
        }

        // TODO remove once c++ client is fixed
        final String cleanedToken = token.trim();
        return validateToken(cleanedToken);
    }

    @Override
    public AuthenticationState newAuthState(AuthData authData, SocketAddress remoteAddress, SSLSession sslSession)
            throws AuthenticationException {
        final String token = tokenFromAuthData(authData);
        if (isEmpty(token)) {
            throw new AuthenticationException("missing client token");
        }

        // TODO remove once c++ client is fixed
        final String cleanedToken = token.trim();
        final String role = validateToken(cleanedToken);

        return new TokenAuthenticationState(this, tokenCache, remoteAddress, sslSession,
                cleanedToken, role);
    }

    String tokenFromSource(AuthenticationDataSource authenticationDataSource) throws AuthenticationException {
        if (Objects.isNull(authenticationDataSource)) {
            throw new IllegalArgumentException("No AuthenticationDataSource provided");
        }

        if (authenticationDataSource.hasDataFromCommand()) {
            return authenticationDataSource.getCommandData();
        } else if (authenticationDataSource.hasDataFromHttp()) {
            // Authentication HTTP request. The format here should be compliant to RFC-6750
            // (https://tools.ietf.org/html/rfc6750#section-2.1). Eg: Authorization: Bearer xxxxxxxxxxxxx
            String httpHeaderValue = authenticationDataSource.getHttpHeader(HTTP_HEADER_NAME);
            if (httpHeaderValue == null || !httpHeaderValue.startsWith(HTTP_HEADER_VALUE_PREFIX)) {
                throw new AuthenticationException("Invalid HTTP Authorization header");
            }

            // Remove prefix
            return httpHeaderValue.substring(HTTP_HEADER_VALUE_PREFIX.length()).trim();
        }

        throw new AuthenticationException("No token credentials passed");
    }

    private String validateToken(final String token) throws AuthenticationException {
        if (isEmpty(token)) {
            throw new AuthenticationException("Blank token found");
        }

        final CompletableFuture<String> future = tokenCache.get(token, (t, executor) -> {
            CompletableFuture<String> tokenInfoFuture = new CompletableFuture<>();
            executor.execute(() -> {
                try {
                    final String vaultAddress = vaultAddress();
                    final String lookupPath = DEFAULT_VAULT_LOOKUP_PATH;
                    final String url = String.format("%s%s", vaultAddress, lookupPath);
                    Log.info("making auth request url=" + url);
                    final RestResponse response = new Rest()
                            .url(url)
                            .header(VAULT_TOKEN_HEADER, token)
                            .get();
                    // did we get a valid response?
                    if (response.getStatus() < 200 || response.getStatus() > 299) {
                        final String message = new String(response.getBody());
                        Log.severe("failed to authenticate token status="
                                + response.getStatus() + " error=" + message);
                        tokenInfoFuture.completeExceptionally(new AuthenticationException(message));
                        return;
                    }

                    final JsonValue jv = Json.parse(new String(response.getBody()));
                    // did we get a response?
                    if (jv == null || jv.isNull()) {
                        Log.severe("malformed response from Vault missing response body");
                        tokenInfoFuture.completeExceptionally(
                                new RuntimeException("Malformed response from Vault missing response body"));
                        return;
                    }

                    final JsonValue dataValue = jv.asObject().get("data");
                    // did we get a data object in the response?
                    if (dataValue == null || dataValue.isNull() || !dataValue.isObject()) {
                        Log.severe("malformed response from Vault missing data object");
                        tokenInfoFuture.completeExceptionally(
                                new RuntimeException("Malformed response from Vault missing data object"));
                        return;
                    }

                    final String role = Helper.roleFromResponseData(dataValue.asObject());
                    Log.info("success validated token role=" + role);
                    tokenInfoFuture.complete(role);
                } catch (Exception e) {
                    tokenInfoFuture.completeExceptionally(new RuntimeException(e));
                }
            });

            return tokenInfoFuture;
        });

        try {
            return future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException | TimeoutException | ExecutionException e) {
            if (e.getCause() instanceof AuthenticationException) {
                throw (AuthenticationException) e.getCause();
            } else if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            }
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAuthMethodName() {
        return "token";
    }

    @Override
    public void close() throws IOException {
        executorService.shutdownNow();
    }

    private static class RandomExpiry implements Expiry<String, String> {

        final Random random = new Random();
        final long minDuration;
        final int interval;

        private RandomExpiry(long minDuration, int interval) {
            this.minDuration = minDuration;
            this.interval = interval;
        }

        @Override
        public long expireAfterCreate(String key, String value, long currentTime) {
            final long seconds = minDuration + (long) random.nextInt(interval);
            return TimeUnit.SECONDS.toNanos(seconds);
        }

        @Override
        public long expireAfterUpdate(String key, String value, long currentTime, long currentDuration) {
            return currentDuration;
        }

        @Override
        public long expireAfterRead(String key, String value, long currentTime, long currentDuration) {
            return currentDuration;
        }
    }

    static final class TokenAuthenticationState implements AuthenticationState {
        private final AuthenticationProvider provider;
        private AsyncLoadingCache<String, String> tokens;
        private final SocketAddress remoteAddress;
        private final SSLSession sslSession;

        private AuthenticationDataSource authenticationDataSource;
        private String token;
        private String role;

        TokenAuthenticationState(
                AuthenticationProvider provider,
                AsyncLoadingCache<String, String> tokens,
                SocketAddress remoteAddress,
                SSLSession sslSession,
                String token,
                String role) throws AuthenticationException {
            this.provider = provider;
            this.tokens = tokens;
            this.remoteAddress = remoteAddress;
            this.sslSession = sslSession;
            this.token = token;
            this.role = role;
        }

        @Override
        public String getAuthRole() throws AuthenticationException {
            return role;
        }

        @Override
        public AuthData authenticate(AuthData authData) throws AuthenticationException {
            String token = tokenFromAuthData(authData);
            final AuthenticationDataSource dataCommand =
                    new AuthenticationDataCommand(token, remoteAddress, sslSession);
            final String role = provider.authenticate(dataCommand);

            this.authenticationDataSource = dataCommand;
            this.token = token;
            this.role = role;

            // There's no additional auth stage required
            return null;
        }

        @Override
        public AuthenticationDataSource getAuthDataSource() {
            return authenticationDataSource;
        }

        @Override
        public boolean isComplete() {
            // The authentication of tokens is always done in one single stage
            return true;
        }

        @Override
        public boolean isExpired() {
            if (isEmpty(token) || isEmpty(role)) {
                return true;
            }
            try {
                final CompletableFuture<String> future = tokens.getIfPresent(token);
                if (future == null || !future.isDone() || future.isCompletedExceptionally()) {
                    // token is expired or being reloaded force re-authentication
                    return true;
                }
                final String cachedRole = future.get();
                return !Objects.equals(role, cachedRole);
            } catch (Exception ex) {
                // ignore
            }

            return true;
        }
    }

    private static String tokenFromAuthData(AuthData authData) {
        return new String(authData.getBytes(), StandardCharsets.UTF_8);
    }

    static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }

    /**
    * Code taken from java source code. Added a constructor to set the thread pool name
    */
    private static class DefaultThreadFactory implements ThreadFactory {
        private static final AtomicInteger poolNumber = new AtomicInteger(1);
        private final ThreadGroup group;
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String namePrefix;
        private final String poolName;

        private DefaultThreadFactory(String poolName) {
            this.poolName = poolName;
            SecurityManager s = System.getSecurityManager();
            group = (s != null) ? s.getThreadGroup() :
                    Thread.currentThread().getThreadGroup();
            namePrefix = poolName + poolNumber.getAndIncrement() + "-";
        }

        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r,
                    namePrefix + threadNumber.getAndIncrement(),
                    0);
            if (t.isDaemon())
                t.setDaemon(false);
            if (t.getPriority() != Thread.NORM_PRIORITY)
                t.setPriority(Thread.NORM_PRIORITY);
            return t;
        }

        public static ThreadFactory create(String poolName) {
            return new DefaultThreadFactory(poolName);
        }
    }
}
