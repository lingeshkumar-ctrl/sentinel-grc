FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -o iam-service main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/iam-service .
EXPOSE 8081
CMD ["./iam-service"]
