# https://github.com/yeasy/docker-hyperledger-fabric-peer
FROM yeasy/hyperledger-fabric-base:1.4.2
WORKDIR $GOPATH

COPY . .
COPY store/vendor/ $GOPATH/src
COPY core.yaml /var/hyperledger/config/core.yaml
RUN go build -buildmode=plugin -o=customEndorsement.so custom_endorsement.go
RUN mkdir /etc/hyperledger/fabric/plugins
RUN cp customEndorsement.so /etc/hyperledger/fabric/plugins

RUN go build -buildmode=plugin -o=customValidation.so custom_validation.go
RUN cp customValidation.so /etc/hyperledger/fabric/plugins

RUN cd $FABRIC_ROOT/peer \
    && CGO_CFLAGS=" " go install -tags "" -ldflags "$LD_FLAGS" \
    && go clean

EXPOSE 7051
CMD tail -f /dev/null