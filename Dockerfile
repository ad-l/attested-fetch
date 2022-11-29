# For simplicity, we use the LVI wrappers created by the CCF build, which aren't
# present in the basic OE image.
FROM antdl/ccf:latest

ENV DEBIAN_FRONTEND noninteractive

ADD . /var/src
WORKDIR /var/src
RUN /var/src/build.sh
ENTRYPOINT ["/var/src/dist/afetch", "/var/src/dist/libafetch.enclave.so.signed"]
