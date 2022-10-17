FROM docker pull python:3.9.15-slim-bullseye:3.9.6 AS builder
WORKDIR /build
COPY setup.py /build/
COPY src /build/src
RUN pip3 install .

RUN rm -rf /build
WORKDIR /
ENTRYPOINT ["python3", "-m", "connectors"]