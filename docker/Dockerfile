FROM python:3.9.18

ARG USERNAME=flask
ARG USER_UID=1001
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash \
    && apt-get update \
    && apt-get -y install --no-install-recommends libsasl2-dev libldap2-dev libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY . /app
WORKDIR /app/

ENV PYTHONPATH=/app

RUN pip3 install gunicorn && pip install -r /app/requirements.txt


RUN chown -R $USERNAME:$USERNAME /app

COPY ./docker/start.sh /home/$USERNAME/.local/bin/start.sh
RUN chmod +x /home/$USERNAME/.local/bin/start.sh

# Set the default user.
USER $USERNAME

ENV PATH=$PATH:/home/$USERNAME/.local/bin
ENV TIMEOUT 60
ENV ENABLE_HTTPS False
ENV WORKERS 1

EXPOSE 5001

CMD ["start.sh"]
