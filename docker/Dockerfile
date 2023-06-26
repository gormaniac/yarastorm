FROM vertexproject/synapse:v2.x.x

COPY scripts/install-yara.sh /build/yarastorm/install-yara.sh
COPY docker/bootstrap.sh /build/yarastorm/bootstrap.sh
COPY pyproject.toml /build/yarastorm/pyproject.toml
COPY src/yarastorm /build/yarastorm/src/yarastorm
COPY README.md /build/yarastorm/README.md
COPY LICENSE /build/yarastorm/LICENSE

RUN /build/yarastorm/bootstrap.sh

COPY docker/entrypoint.sh /vertex/synapse/entrypoint.sh

EXPOSE 4443
EXPOSE 27492

VOLUME /vertex/storage

ENTRYPOINT ["tini", "--", "/vertex/synapse/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD python -m synapse.tools.healthcheck -c cell:///vertex/storage/