package com.github.cckellogg.pulsar.vault.functions.auth;

import io.kubernetes.client.apis.CoreV1Api;
import io.kubernetes.client.models.V1StatefulSet;

import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationProviderToken;
import org.apache.pulsar.functions.instance.AuthenticationConfig;
import org.apache.pulsar.functions.auth.FunctionAuthData;
import org.apache.pulsar.functions.auth.KubernetesFunctionAuthProvider;
import org.apache.pulsar.functions.proto.Function;

import java.util.Optional;
import java.util.logging.Logger;

public class VaultKubernetesFunctionAuthProvider implements KubernetesFunctionAuthProvider {

    private static final Logger Log =
            Logger.getLogger(VaultKubernetesFunctionAuthProvider.class.getName());

    private static final String DEFAULT_TOKEN_PATH = "/vault/secrets/token";
    private static final String DEFAULT_CLIENT_AUTH_PROVIDER =
            "org.apache.pulsar.client.impl.auth.AuthenticationToken";

    @Override
    public void initialize(CoreV1Api coreV1Api) {
    }

    @Override
    public void configureAuthDataStatefulSet(V1StatefulSet v1StatefulSet, Optional<FunctionAuthData> optional) {
    }

    @Override
    public void configureAuthenticationConfig(AuthenticationConfig authConfig,
            Optional<FunctionAuthData> functionAuthData) {
        if (functionAuthData.isPresent()) {
            final String authParams = String.format("file://%s", DEFAULT_TOKEN_PATH);
            Log.info(String.format("function client config auth_plugin=%s, auth_params=%s",
                    DEFAULT_CLIENT_AUTH_PROVIDER, authParams));
            authConfig.setClientAuthenticationPlugin(DEFAULT_CLIENT_AUTH_PROVIDER);
            authConfig.setClientAuthenticationParameters(authParams);
        } else {
            Log.info("missing function auth data");
            // if auth data is not present maybe user is trying to use anonymous role
            // thus don't pass in any auth config
            authConfig.setClientAuthenticationPlugin(null);
            authConfig.setClientAuthenticationParameters(null);
        }
    }

    @Override
    public Optional<FunctionAuthData> cacheAuthData(Function.FunctionDetails functionDetails,
            AuthenticationDataSource authenticationDataSource) throws Exception {
        final String token = AuthenticationProviderToken.getToken(authenticationDataSource);
        if (isEmpty(token)) {
            return Optional.empty();
        }

        return Optional.of(FunctionAuthData.builder().data("vault".getBytes()).build());
    }

    @Override
    public Optional<FunctionAuthData> updateAuthData(Function.FunctionDetails functionDetails,
            Optional<FunctionAuthData> optional, AuthenticationDataSource authenticationDataSource) throws Exception {
        final String token = AuthenticationProviderToken.getToken(authenticationDataSource);
        if (isEmpty(token)) {
            return Optional.empty();
        }

        return Optional.of(FunctionAuthData.builder().data("vault".getBytes()).build());
    }

    @Override
    public void cleanUpAuthData(Function.FunctionDetails functionDetails, Optional<FunctionAuthData> optional)
            throws Exception {
        // no clean up needed
    }

    static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }
}
