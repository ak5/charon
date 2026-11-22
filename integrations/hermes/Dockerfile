FROM python:3.15.2-slim-bookworm@sha256:96599df822d0e1c6bb700014a05c7f3c8cabc6e0f7ff3c4f9f69cee033b4b5d9

USER root
WORKDIR /opt/charon-hermes
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /opt/charon-hermes/wheels . \
 && python -m pip install --no-cache-dir /opt/charon-hermes/wheels/charon_hermes-*.whl \
 && python -m pip check

USER 10000:10000
ENTRYPOINT ["charon-hermes-admission"]
