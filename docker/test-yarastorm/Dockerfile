FROM vertexproject/synapse:v2.x.x

COPY scripts/install-yara.sh /build/yarastorm/install-yara.sh
COPY docker/yarastorm/bootstrap.sh /build/yarastorm/bootstrap.sh
COPY pyproject.toml /build/yarastorm/pyproject.toml
COPY src/yarastorm /build/yarastorm/src/yarastorm
COPY README.md /build/yarastorm/README.md
COPY LICENSE /build/yarastorm/LICENSE

RUN /build/yarastorm/bootstrap.sh

COPY tests /build/yarastorm/tests

RUN python -m pip install --break-system-packages pytest pytest-asyncio

COPY docker/test-yarastorm/entrypoint.sh /vertex/synapse/entrypoint.sh

EXPOSE 4443
EXPOSE 27492

VOLUME /vertex/storage

ENTRYPOINT ["tini", "--", "/vertex/synapse/entrypoint.sh"]
