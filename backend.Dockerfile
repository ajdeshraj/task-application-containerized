# syntax docker/dockerfile:1

FROM golang:1.19

WORKDIR /app

COPY go.mod go.sum .
COPY .env .
COPY main.go .
COPY ./initializers/ /usr/local/go/src/webapp/initializers
COPY ./middleware/ /usr/local/go/src/webapp/middleware
COPY ./models/ /usr/local/go/src/webapp/models
COPY ./routes/ /usr/local/go/src/webapp/routes
COPY ./utils/ /usr/local/go/src/webapp/utils

RUN go mod download

RUN GOOS=linux go build -o /app/main /app/main.go

EXPOSE 8080

CMD ["/app/main"]
