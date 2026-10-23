# syntax=docker/dockerfile:1
# Production image: static Go binary with the embedded web bundle on a
# distroless, non-root base. No shell, compiler, or package manager ships in
# the final stage (docs/SECURITY_ARCHITECTURE.md section 10). `make build`
# verifies this with tools/imagecheck.

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26.10-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS go
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd/ cmd/
COPY internal/ internal/
COPY migrations/ migrations/
COPY --from=web /src/internal/platform/webui/dist/app/ internal/platform/webui/dist/app/
RUN go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/qali ./cmd/qali

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=go /out/qali /usr/local/bin/qali
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/qali"]
