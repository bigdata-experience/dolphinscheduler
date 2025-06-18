docker buildx build --platform=linux/amd64,linux/arm64 \
--build-arg DOCKER_PULL_SERVER=od-registry.tyszxc.com \
--build-arg PYPI_GROUP=https://nx.tyszxc.com/repository/pypi-group/simple/ \
--build-arg ARTIFACT_HOST=https://nx.tyszxc.com/repository/raw-hosted \
-t dh-registry.tyszxc.com/apache/dolphinscheduler-api:v3.2.2-20250618 -f src/main/docker/Dockerfile --push .