# Build. Base images are pinned by digest; Dependabot proposes updates.
FROM golang:1.26@sha256:6e59e17a20f13c102e49d82dffab66d41cffe6c266b225d82794328aea859ab5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ostiara ./cmd/ostiara

# Run: static binary on distroless, as numeric nonroot user (needed for runAsNonRoot)
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /ostiara /ostiara
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ostiara", "broker"]
