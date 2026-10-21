FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/silentfabric ./cmd/silentfabric

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/silentfabric /usr/local/bin/silentfabric
COPY rules /etc/silentfabric/rules
ENV SF_RULES_DIR=/etc/silentfabric/rules
EXPOSE 5514/udp 5514/tcp 8080/tcp
ENTRYPOINT ["silentfabric"]
CMD ["serve"]
