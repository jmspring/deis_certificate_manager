FROM python:2.7-alpine

ENV INSTALL_PATH /app
RUN mkdir -p $INSTALL_PATH

WORKDIR $INSTALL_PATH

ADD requirements.txt /tmp/requirements.txt

RUN apk add --no-cache --virtual .build-deps \
    build-base libffi-dev openssl-dev \
  	&& pip install -r /tmp/requirements.txt \
	&& rm /tmp/requirements.txt \
	&& apk del .build-deps \
	&& apk add --no-cache bash 

COPY . . 

EXPOSE 5000

ENTRYPOINT ["python"]
CMD ["deis_certificate_manager.py"]
