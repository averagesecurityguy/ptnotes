FROM alpine
MAINTAINER Jayson Grace <jayson.e.grace@gmail.com>

# Install flask and various dependencies
RUN apk add --no-cache py2-pip \
&& pip2 install --upgrade pip \
&& pip2 install flask

# Setup the ptnotes user, project, and folder permissions
RUN adduser -h /ptnotes -g ptnotes -D ptnotes
COPY . /ptnotes
RUN chown -R ptnotes:ptnotes /ptnotes
RUN chmod +x /ptnotes/server
USER ptnotes

WORKDIR /ptnotes

EXPOSE 5000

CMD ["./server", "-l", "0.0.0.0"]
