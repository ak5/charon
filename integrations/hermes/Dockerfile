FROM python:3.15.0-slim-bookworm@sha256:122756f3fe72c4f5d3d71897888204ee85774bc79de952555b8a474e1d0a5d53

USER root
WORKDIR /opt/charon-hermes
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /opt/charon-hermes/wheels . \
 && python -m pip install --no-cache-dir /opt/charon-hermes/wheels/charon_hermes-*.whl \
 && python -m pip check

USER 10000:10000
ENTRYPOINT ["charon-hermes-admission"]
