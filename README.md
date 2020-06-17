# pulsar-vault


## Requirements
- [bazel](https://docs.bazel.build/versions/master/install.html)
- [docker](https://docs.docker.com/get-docker/)

## Build

#### Authentication plugin
```
bazel build pulsar/src/main/java:pulsar-vault-auth

output-jar:
bazel-bin/pulsar/src/main/java/pulsar-vault-auth.jar
```

#### Kubernetes plugins
```
bazel build pulsar/src/main/java:pulsar-vault-function-plugins

output-jar:
bazel-bin/pulsar/src/main/java/pulsar-vault-function-plugins.jar
```

#### Docker image
Build an image with the vault plugins packaged into Pulsar.

```
bazel build docker:pulsar

docker-tar:
bazel-bin/docker/pulsar-layer.tar
```


