FROM python:3.9.6 AS builder
WORKDIR /build
COPY setup.py /build/
COPY src /build/src
RUN pip3 install .

RUN groupadd --gid 2866 dash4ast \
    && useradd --home-dir /home/dash4ast --create-home --uid 2866 \
        --gid 2866 --shell /bin/sh --skel /dev/null dash4ast

RUN rm -rf /build
WORKDIR /
ENTRYPOINT ["python3", "-m", "connectors"]
