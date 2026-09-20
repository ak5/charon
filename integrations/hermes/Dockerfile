FROM python:3.14.6-slim-bookworm@sha256:4c92ffcde4dd6f1ff72a24518f49fd4990b27134987dfa31a733badde66df9f8

USER root
WORKDIR /opt/charon-hermes
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /opt/charon-hermes/wheels . \
 && python -m pip install --no-cache-dir /opt/charon-hermes/wheels/charon_hermes-*.whl \
 && python -m pip check

USER 10000:10000
ENTRYPOINT ["charon-hermes-admission"]
