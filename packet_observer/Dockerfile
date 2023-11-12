FROM rust:1.72.0
WORKDIR /usr/src/myapp
COPY . .
RUN apt-get update && \
    apt-get install -y libpcap-dev && \
    cargo install --path .

# replace to pcap file you wish to observe
CMD ["packet_observer", "example.pcap"]

