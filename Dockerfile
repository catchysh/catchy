FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM

WORKDIR /

COPY ${TARGETPLATFORM}/catchy /catchy
COPY public/ /public/

ENTRYPOINT ["/catchy"]

CMD ["serve"]
