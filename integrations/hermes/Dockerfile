FROM python:3.12.10-slim-bookworm@sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db

USER root
WORKDIR /opt/charon-hermes
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /opt/charon-hermes/wheels . \
 && python -m pip install --no-cache-dir /opt/charon-hermes/wheels/charon_hermes-*.whl \
 && python -m pip check

USER 10000:10000
ENTRYPOINT ["charon-hermes-admission"]
