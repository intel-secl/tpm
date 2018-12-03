FROM davidczech/tpm-sim:latest

WORKDIR /root
RUN curl -L https://dl.google.com/go/go1.11.2.linux-amd64.tar.gz > go.tar.gz && tar -C /usr/local -xzf go.tar.gz
ENV PATH ${PATH}:/usr/local/go/bin

ENTRYPOINT "bash"
