ARG PYTHON_VERSION=3.9.18

FROM python:${PYTHON_VERSION}

ARG USERNAME=flask
ARG USER_UID=1001
ARG USER_GID=${USER_UID}

# Create the user
RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME} -s /bin/bash \
    && apt-get update \
    && apt-get -y install --no-install-recommends libsasl2-dev libldap2-dev libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH=${PATH}:/home/${USERNAME}/.local/bin
USER ${USERNAME}

COPY --chown=${USERNAME}:${USERNAME} ./requirements.txt /app/requirements.txt
RUN pip3 install --user gunicorn \
    && pip install --user --no-cache-dir --upgrade -r /app/requirements.txt

COPY --chown=${USERNAME}:${USERNAME} ./app /app/app
COPY --chown=${USERNAME}:${USERNAME} ./config /app/config
COPY --chown=${USERNAME}:${USERNAME} ./migrations /app/migrations
COPY --chown=${USERNAME}:${USERNAME} ./orchdashboard.py /app/orchdashboard.py
COPY --chown=${USERNAME}:${USERNAME} ./docker/start.sh /home/${USERNAME}/.local/bin/start.sh

WORKDIR /app/

ENV PYTHONPATH=/app
ENV TIMEOUT=60
ENV ENABLE_HTTPS=False
ENV WORKERS=1

EXPOSE 5001

CMD ["start.sh"]
