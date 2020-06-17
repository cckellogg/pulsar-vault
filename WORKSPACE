load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")


RULES_JVM_EXTERNAL_TAG = "2.8"
RULES_JVM_EXTERNAL_SHA = "79c9850690d7614ecdb72d68394f994fef7534b292c4867ce5e7dec0aa7bdfad"

http_archive(
    name = "rules_jvm_external",
    strip_prefix = "rules_jvm_external-%s" % RULES_JVM_EXTERNAL_TAG,
    sha256 = RULES_JVM_EXTERNAL_SHA,
    url = "https://github.com/bazelbuild/rules_jvm_external/archive/%s.zip" % RULES_JVM_EXTERNAL_TAG,
)

load("@rules_jvm_external//:defs.bzl", "maven_install")

PULSAR_VERSION = "2.5.2"
VAULT_JAVA_VERSION = "5.1.0"

#pulsar_deps = []

#"io.kubernetes:client-java-api:3.0.0",
# compile group: 'org.apache.pulsar', name: 'pulsar-functions-proto', version: '2.5.2'
maven_install(
    artifacts = [
        "org.apache.pulsar:pulsar-client-api:%s" % PULSAR_VERSION,
        "org.apache.pulsar:pulsar-broker-common:%s" % PULSAR_VERSION,
        "org.apache.pulsar:pulsar-functions-proto:%s" % PULSAR_VERSION,
        "org.apache.pulsar:pulsar-functions-runtime:%s" % PULSAR_VERSION,
        "org.apache.pulsar:pulsar-functions-instance:%s" % PULSAR_VERSION,
        "com.github.ben-manes.caffeine:caffeine:2.6.2",
        "com.bettercloud:vault-java-driver:%s" % VAULT_JAVA_VERSION,
        "io.kubernetes:client-java-api:3.0.0",
        "com.google.code.gson:gson:2.8.5",
    ],
    fetch_sources = True,
    repositories = [
        "https://repo1.maven.org/maven2",
    ],
)


# Download the rules_docker repository at release v0.14.3
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "6287241e033d247e9da5ff705dd6ef526bac39ae82f3d17de1b69f8cb313f9cd",
    strip_prefix = "rules_docker-0.14.3",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.14.3/rules_docker-v0.14.3.tar.gz"],
)

load(
    "@io_bazel_rules_docker//repositories:repositories.bzl",
    container_repositories = "repositories",
)
container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
)


container_pull(
    name = "pulsar_base",
    registry = "index.docker.io",
    repository = "apachepulsar/pulsar",
    tag = PULSAR_VERSION,
    # 'tag' is also supported, but digest is encouraged for reproducibility.
    digest = "sha256:e9daf604d06dab912a1b68b7821275ef9a0d370172ba375098eff409e777ab32",
)

