FROM golang:1.26.10 AS build
WORKDIR /fixture
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/application-fixture .
FROM scratch
COPY --from=build /out/application-fixture /application-fixture
COPY THIRD_PARTY_LICENSES.txt /THIRD_PARTY_LICENSES.txt
USER 65532:65532
ENTRYPOINT ["/application-fixture"]
