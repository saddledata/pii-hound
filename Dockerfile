# Small Dockerfile for pii-hound
FROM scratch
COPY pii-hound /usr/local/bin/pii-hound
ENTRYPOINT ["/usr/local/bin/pii-hound"]
CMD ["--help"]
