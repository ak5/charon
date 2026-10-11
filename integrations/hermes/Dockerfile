FROM python:3.14.8-slim-bookworm@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83

USER root
WORKDIR /opt/charon-hermes
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /opt/charon-hermes/wheels . \
 && python -m pip install --no-cache-dir /opt/charon-hermes/wheels/charon_hermes-*.whl \
 && python -m pip check

USER 10000:10000
ENTRYPOINT ["charon-hermes-admission"]
