# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o redgem_bruter ./cmd/redgem_bruter

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache nmap

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/redgem_bruter .

# Create a non-root user
RUN adduser -D -g '' appuser
USER appuser

# Command to run the application
ENTRYPOINT ["./redgem_bruter"] 