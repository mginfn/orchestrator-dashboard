FROM python:3.7

COPY . /app
WORKDIR /app/

ENV PYTHONPATH=/app

RUN apt-get update && \
apt-get -y install --no-install-recommends libsasl2-dev python-dev libldap2-dev libssl-dev && \
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


RUN pip3 install gunicorn && pip install -r /app/requirements.txt

EXPOSE 5001

ENV TIMEOUT 60
ENV ENABLE_HTTPS False
ENV WORKERS 1

COPY ./docker/start.sh /start.sh

CMD ["/bin/bash","/start.sh"]



