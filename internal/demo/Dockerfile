# Minimal isolation image to exercise the Shai-Hulud npm IOC policy with Deputy
# without touching the host. Builds deputy in a separate stage, ships only the
# binary and the policy, and runs as an unprivileged user.

FROM golang:1.25-bookworm AS builder
WORKDIR /src

# Pre-fetch modules
COPY go.mod go.sum ./
RUN go mod download

# Build deputy
COPY . .
RUN CGO_ENABLED=0 go build -o /out/deputy ./main.go

FROM node:20-bookworm
# Create a non-root user for running tests
RUN useradd -m tester
WORKDIR /app

# Bring in deputy binary and the policy file(s) needed for tests
COPY --from=builder /out/deputy /usr/local/bin/deputy
COPY policy/examples/shai-hulud-npm.yaml /app/policy/examples/
COPY internal/demo/POLICY_PROXY.md /app/internal/demo/

RUN apt-get update && apt-get install -y vim

RUN chown -R tester:tester /app
USER tester
ENV PATH="/usr/local/bin:${PATH}"

# Default command just prints help; override in `docker run`.
CMD ["deputy", "--help"]
