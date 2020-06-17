package com.github.cckellogg.pulsar.vault.functions.runtime;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import io.kubernetes.client.models.V1ObjectMeta;
import io.kubernetes.client.models.V1PodTemplateSpec;
import io.kubernetes.client.models.V1Service;
import io.kubernetes.client.models.V1StatefulSet;

import org.apache.pulsar.functions.proto.Function;
import org.apache.pulsar.functions.runtime.kubernetes.KubernetesManifestCustomizer;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class VaultKubernetesManifestCustomizer implements KubernetesManifestCustomizer {

    private static final Logger Log =
            Logger.getLogger(VaultKubernetesManifestCustomizer.class.getName());

    private static final class RuntimeOptions {
        private String namespace;
        private String serviceAccountName;
    }

    private static final class SecretObject {
        private String path;
        private String key;
        private boolean kv2;
    }

    static final String kv1TemplateFormat =
            "{{- with secret \"%s\" }}" +
                    "{{ .Data.%s }}" +
                    "{{ end }}";

    static final String kv2TemplateFormat =
            "{{- with secret \"%s\" }}" +
            "{{ .Data.data.%s }}" +
            "{{ end }}";

    @Override
    public void initialize(Map<String, Object> config) {
    }

    @Override
    public String customizeNamespace(Function.FunctionDetails functionDetails,
            String currentNamespace) {
        final RuntimeOptions opts = getRuntimeOptions(functionDetails);
        if (isEmpty(opts.namespace)) {
            return currentNamespace;
        }

        Log.info(String.format("updating kubernetes namespace for function=%s" +
                " current_namespace=%s new_namespace=%s",
                fqn(functionDetails), currentNamespace, opts.namespace));
        return opts.namespace;
    }

    @Override
    public V1Service customizeService(Function.FunctionDetails functionDetails,
            V1Service service) {
        return service;
    }

    @Override
    public V1StatefulSet customizeStatefulSet(Function.FunctionDetails functionDetails,
            V1StatefulSet statefulSet) {
        final RuntimeOptions opts = getRuntimeOptions(functionDetails);
        final V1PodTemplateSpec podTemplateSpec = statefulSet.getSpec().getTemplate();

        // should we set the service account?
        if (!isEmpty(opts.serviceAccountName)) {
            Log.info(String.format("updating kubernetes service account function=%s" +
                    " service_account_name=%s",
                    fqn(functionDetails), opts.serviceAccountName));
            podTemplateSpec.getSpec().setServiceAccountName(opts.serviceAccountName);
        }

        // add vault annotations
        final V1ObjectMeta podMeta = podTemplateSpec.getMetadata();
        final String vaultRole = isEmpty(podTemplateSpec.getSpec().getServiceAccountName()) ?
                "default" : podTemplateSpec.getSpec().getServiceAccountName();
        final Map<String, String> vaultAnnotations = vaultAnnotations(vaultRole);
        vaultAnnotations.forEach(podMeta::putAnnotationsItem);

        // are there any secrets?
        if (!isEmpty(functionDetails.getSecretsMap())) {
            final String secretsString = functionDetails.getSecretsMap();
            final Type type = new TypeToken<Map<String, SecretObject>>(){}.getType();
            final Map<String, SecretObject> secrets =
                    new Gson().fromJson(secretsString, type);

            // generate secret templates
            // for each secret key
            // generate an file with the key's value
            Map<String, String> vaultSecretAnnotations = new HashMap<>();
            secrets.forEach((k, so) -> {
                vaultSecretAnnotations.put(
                    "vault.hashicorp.com/agent-inject-secret-" + k,
                    so.path);
                // add custom rendering template
                final String templateFormat = so.kv2 ?
                        kv2TemplateFormat : kv1TemplateFormat;
                final String template =
                        String.format(templateFormat, so.path, so.key);
                vaultSecretAnnotations.put(
                    "vault.hashicorp.com/agent-inject-template-" + k,
                    template);
            });

            vaultSecretAnnotations.forEach(podMeta::putAnnotationsItem);
        }

        return statefulSet;
    }

    private Map<String, String> vaultAnnotations(String role) {
        final Map<String, String> annotations = new HashMap<>();
        annotations.put("vault.hashicorp.com/agent-inject", "true");
        annotations.put("vault.hashicorp.com/agent-inject-token", "true");
        annotations.put("vault.hashicorp.com/role", role);

        return annotations;
    }

    private RuntimeOptions getRuntimeOptions(Function.FunctionDetails functionDetails) {
        String customRuntimeOptions = functionDetails.getCustomRuntimeOptions();
        RuntimeOptions opts =
                new Gson().fromJson(customRuntimeOptions, RuntimeOptions.class);

        return opts != null ? opts : new RuntimeOptions();
    }

    private String fqn(Function.FunctionDetails functionDetails) {
        return String.format("%s/%s/%s",
                functionDetails.getTenant(),
                functionDetails.getNamespace(),
                functionDetails.getName());
    }

    private static boolean isEmpty(String s) {
        return s == null || s.length() == 0;
    }
}
