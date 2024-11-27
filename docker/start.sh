#!/bin/bash

CA_BUNDLE_PATH=$(python3 -m certifi)

CERT_PATH=${CERT_PATH:-"/trusted_certs"}
TIMEOUT=${TIMEOUT:-"60"}
WORKERS=${WORKERS:-"1"}
CERT=${CERT:-"/certs/cert.pem"}
KEY=${KEY:-"/certs/key.pem"}
PORT=${PORT:-"5001"}

if [ ! -d "${CERT_PATH}" ]; then
   echo "${CERT_PATH} does not exist. Nothing to do..."
else
  cd "${CERT_PATH}"

  for cert in `ls *.pem`; do
    md5res=`md5sum $cert`
    md5sum_str=`echo "$md5res" | cut -d' ' -f1`
    grep "$md5sum_str" .added_certs &> /dev/null
    if [ $? == 0 ]; then
          echo "Cert $cert alredy added"
    else
       echo "Adding Cert from file $cert to the CA bundle"
       cat $cert >> "$CA_BUNDLE_PATH" && echo "$md5res" >> .added_certs
    fi
  done

  cd -
fi  


if [ "${ENABLE_HTTPS,}" == "true" ]; then
  if test -e "$CERT" && test -f "$KEY" ; then
    exec gunicorn --bind 0.0.0.0:$PORT -w "$WORKERS" --certfile "$CERT" --keyfile "$KEY" --timeout "$TIMEOUT"  orchdashboard:app
  else
    echo "[ERROR] File $CERT or $KEY NOT FOUND!"
    exit 1
  fi
else
  exec gunicorn --bind 0.0.0.0:$PORT -w "$WORKERS" --timeout "$TIMEOUT"  orchdashboard:app
fi
