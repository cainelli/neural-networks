FROM alpine:3.3
RUN mkdir -p /opt/normaliz
RUN mkdir -p /opt/normaliz/log
WORKDIR /opt/normaliz
ADD requirements.txt /opt/normaliz/
RUN apk add --update \
    python \
    python-dev \
    py-pip \
    build-base \
  && pip install -r /opt/normaliz/requirements.txt \
  && rm -rf /var/cache/apk/*

EXPOSE 8080
CMD ["python", "app.py"]