# Used by GoReleaser (dockers_v2). It copies the binary GoReleaser already built for each
# platform, it does not compile anything. A plain `docker build .` does not work for that reason.
#
# distroless/static carries CA certificates and an unprivileged user (65532), and has no shell
# and no package manager. The digest pins the base image; update it deliberately.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/uptimeify /uptimeify
USER 65532:65532
ENTRYPOINT ["/uptimeify"]
