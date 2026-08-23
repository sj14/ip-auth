# Build stage
FROM golang:1 AS build

WORKDIR /go/src/app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /go/bin/app

# Final stage
FROM gcr.io/distroless/static-debian13
COPY --from=build /go/bin/app /
ENTRYPOINT ["/app"]
