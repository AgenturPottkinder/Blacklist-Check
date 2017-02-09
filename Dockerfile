FROM debian
MAINTAINER Bastian Bringenberg <bastian@agentur-pottkinder.de>

# Required for all services
#ENV FILE=go1.7.4.linux-amd64.tar.gz
#ENV FILEURL=https://storage.googleapis.com/golang/go1.7.4.linux-amd64.tar.gz
#ENV PATH=$PATH:/usr/local/go/bin
#ENV GOPATH=/tmp
#ENV GOBIN=/tmp/go
ENV DEBIAN_FRONTEND=noninteractive
ENV BUILD_PACKAGES="wget tar git golang"

# Please change!
ENV POTTKINDER_REDIRECT=https://www.agentur-pottkinder.de/

# Install wget and tar
RUN apt-get update
RUN apt-get install -y $BUILD_PACKAGES

# Install Go Bundle
WORKDIR /src
RUN mkdir /tmp/go
RUN go get -u github.com/miekg/dns
ADD static/server.go /tmp
RUN go install server.go
RUN mv go/server /server

## Clean Up for filesize
#RUN rm -rf /tmp
#RUN rm -rf /usr/local/go/bin
#RUN AUTO_ADDED_PACKAGES=`apt-mark showauto`
## TODO: Add $BUILD_PACKAGES
#RUN apt-get remove --purge -y $AUTO_ADDED_PACKAGES
#RUN apt-get autoremove -y
#RUN rm -rf /var/lib/apt/lists/*


# Run http server on port 8080
# EXPOSE  80
CMD ["go install server.go -o /build/"]
