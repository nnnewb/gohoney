FROM golang:1.18-bullseye AS BUILD
RUN mkdir -p /workspace
COPY go.mod /workspace/go.mod
COPY go.sum /workspace/go.sum
COPY vendor /workspace/vendor
COPY main.go /workspace/main.go
WORKDIR /workspace
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o sshhighpot main.go

FROM scratch
COPY --from=BUILD /workspace/sshhighpot /sshhighpot
CMD [ "/sshhighpot" ]
