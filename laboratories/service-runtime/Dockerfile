# Dependencies are supplied as reviewed, hash-pinned wheels by the caller.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY requirements.txt /opt/cops-runtime/requirements.txt
COPY wheels/ /opt/cops-runtime/wheels/
RUN python -m pip install --no-index --no-cache-dir --require-hashes \
      --find-links=/opt/cops-runtime/wheels -r /opt/cops-runtime/requirements.txt \
    && rm -rf /opt/cops-runtime/wheels
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["python"]
