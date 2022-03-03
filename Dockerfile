FROM debian:stretch
ADD ./app /app
CMD ["/app", "-vv"]
