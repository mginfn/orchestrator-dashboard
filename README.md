# Orchestrator-dashboard

INDIGO PaaS Orchestrator - Simple Graphical UI

Functionalities:
- IAM authentication
- Display user's deployments
- Display deployment details, template and log
- Delete deployment
- Create new deployment

The orchestrator-dashboard is a Python application built with the [Flask](http://flask.pocoo.org/) microframework; [Flask-Dance](https://flask-dance.readthedocs.io/en/latest/) is used for Openid-Connect/OAuth2 integration.

The docker image uses [Gunicorn](https://gunicorn.org/) as WSGI HTTP server to serve the Flask Application.

# Installation

## Pre-requisites

**The application requires a DB to store data and runs over HTTPS.**

- Running MySQL instance with version 5.7 or 8
    - User with full db administration rights to auto create/manage the database
- Running Redis instance
- Register a client in IAM with the following properties:
    - redirect uri: `https://<DASHBOARD_HOST>:<PORT>/login/iam/authorized`
    - scopes: `openid`, `email`, `profile`, `offline_access`
    - grant_types: `authorization_code`, `refresh_token` e `urn:ietf:params:oauth:grant-type:token-exchange`
        - For the last one the interaction with a IAM administrator may be required.
- Create `instance` folder in top project directory with the following files:
    - `config.json`
- Instruct the app to use certificates
    - If you want to use autogenerate certificates you can use this command
      ```bash=
      openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
      ```
      Place them wherever you want. Just refer to the correct path when using them. 
      **The `launch.json` file and the `docker-compose.yml` expect them to be in the `certs` folder.**

  or use an HTTPS proxy
    - Start the proxy and instruct it to redirect user to the dashboard.
    - Update the client IAM with the correct callback path (i.e. `https://<PROXY_HOST>/login/iam/authorized`).
    - Run the application without certificates.
    - Access the dashboard at `https://<PROXY_HOST>/`


### Local environment

If you want to run the application outside the docker image provided in the repository

- Install package requirements defined in the `requirements.txt`.
  Using pip
  ```bash=
  pip install -r requirements.txt
  ```
  Using poetry
  ```bash=
  cat requirements.txt | xargs poetry add
  ```
  _The installation procedure and the virtual environment activation depends on your preferred way to use them._
  
## Optional configurations

- **If you want to change graphics or automatically enable a set of features choose a pre-configured profile**
    - In `config.json` file, set the `CONFIGURATION_PROFILE` variable (i.e. **infn-cloud**).
- **If you want to enable redis**
    - In `config.json` file, set the `REDIS_URL` variable (i.e. **redis://:my-password@localhost:6379**).
- **If you want to change the upload folder**
    - In `config.json` file, set the `UPLOAD_FOLDER` (i.e. **/opt/uploads**).
- **If you want to display the advanced menu option in the left navbar or enable the scheduling configuration in deployment creation**
    - In `config.json` file, set the `FEATURE_ADVANCED_MENU` equals to **true**.
- **If you want to start the application using the `docker/start.sh` file**
    - Set the environment variable `ENABLE_HTTPS=True` 
- **If you need to install and trust certificates that are not included in the default CA bundle**
    - Create a CA certificate in the `trusted_certs` folder.
- **If you want to integrate the vault service**
    - Add to the `instance` folder `vault-config.json` file.
- **If you want clone manually the tosca-templates repository** 
    - Clone the **tosca-templates** repository and update the `config.json` file so that `TOSCA_TEMPLATES_DIR` points to the correct path (i.e. **/opt/tosca-templates**).
    
      ```bash=
      git clone https://baltig.infn.it/infn-cloud/tosca-templates.git
      ```
      
      **The `docker-compose.yml` expects this resporitory to be in the `instance` folder**.
- **If you want clone manually the dashboard-configuration repository**
    - Clone the **dashboard-configuration** repository and update the `config.json` file so that `SETTINGS_DIR` points to the correct path (i.e. **/opt/dashboard-configuration**).
  
      ```bash=
      git clone https://baltig.infn.it/infn-cloud/dashboard-configuration.git
      ```
  
      **The `docker-compose.yml` expects them to be in the `instance` folder**.
      
      > In `dashboard-configuration/tosca-metadatametadata.yaml` viene definita la mappa tra utenti e servizi disponibili. Si possono mettere regular expressions per definire più gruppi.
- **If you want to enable SSH pub keys**
    - In `config.json` file, set the `FEATURE_REQUIRE_USER_SSH_PUBKEY` equals to **yes**.
    - Enable vault (see next point).
- **If you want to enable vault feature**
    - If you have a vault service, it must be correctly configured. It must grant the correct read, write and delete policies to users. The name of these policies must match the name of the policies set in the `vault-config.json` variables.
    - Il vault deve supportare l'autenticazione tramite JWT token.
    - In `config.json` file, set the `FEATURE_VAULT_INTEGRATION` equals to **yes**.
    - Create a `vault-config.json` file with at least: `VAULT_URL`, `VAULT_ROLE` and `VAULT_BOUND_AUDIENCE`.
- **Use environemnt variable instead of defining variables in `.json` files**
    - Create an environment variable with the **FLASK_** prefix (i.e. `FLASK_TOSCA_TEMPLATES_DIR`)

### `config.json` values

| Key | Description | Mandatory |
| - | - | - |
| SECRET_KEY | Unique identifier for the project | yes |
| IAM_CLIENT_ID | ID of the client registered in IAM | yes | 
| IAM_CLIENT_SECRET | Secret of the client registered in IAM | yes |
| IAM_BASE_URL | IAM url | yes |
| ORCHESTRATOR_URL | Orchestrator service URL | no |
| SLAM_URL | SLAM service URL | yes |
| CMDB_URL | CMDB service URL | no |
| IM_URL | IM service URL | no |
| EXTERNAL_LINKS | Additional external links... | no |
| SQLALCHEMY_DATABASE_URI | Complete URL to the database | yes |
| REDIS_URL | Complete URL to the redis instance. If not set the application tries to contact the localhost. | no |
| CALLBACK_URL | URL contacted by the orchestrator to update the dashboard  | yes |
| ADMINS | List of admin emails. Each email in the list must be written within single quotes. | no | 
| SUPPORT_EMAIL | Email for user support | no |
| IAM_GROUP_MEMBERSHIP | List of user's groups to use in the application. | no |
| CONFIGURATION_PROFILE | Choose dashboard graphics | no |
| LOG_LEVEL | Application log level. Must be upper case. | no |
| ENABLE_HTTPS | Enable HTTPS **only when running the start.sh script**. | no |
| TOSCA_TEMPLATES_DIR | Path to the tosca-templates repository. If it has already been cloned it will upload its content, otherwise its the name of the target folder where to place repository content. | no |
| SETTINGS_DIR | Path to the dashboard-configuration repository. If it has already been cloned it will upload its content, otherwise its the name of the target folder where to place repository content. | no |
| UPLOAD_FOLDER | Path to the folder where uploaded files will be saved. If the folder does not exist, the service will create it as soon as the first item is created. | no |
| FEATURE_ADVANCED_MENU | Enable deployment scheduling and other advanced settings. | no |
| FEATURE_UPDATE_DEPLOYMENT | Enable update/remove advanced option when updating deployments (**DEPRECATED** - Related graphic is not up to date). | no |
| FEATURE_VAULT_INTEGRATION | Enable vault integration. | no |
| FEATURE_REQUIRE_USER_SSH_PUBKEY | Enable section to add user's SSH public key. _Depends on `FEATURE_VAULT_INTEGRATION` since SSH public keys are stored in the vault._ **This is mandatory to submit any deployment.** | no |
| FEATURE_S3CREDS_MENU | Enable menu for S3 credentials creation. **DEPRECATED** | no |
| PROVIDER_NAMES_TO_SPLIT | List of provider names to split in provider name and region name. | no |
| MAIL_SERVER | SMTP server | no |
| MAIL_PORT | SMTP server port | no |
| MAIL_SENDER | Sender email that will appear in the email | no |
| MAIL_USERNAME | Username of the email account to use | no |
| MAIL_PASSWORD | Password of the email account to use | no |
| MAIL_USE_TLS | Use TLS | no |
| LDAP_TLS_CACERT_FILE | CA validated certificate for LDAP | no |
| LDAP_SOCKET | Socket to use to connect to the LDAP instance | no |
| LDAP_BASE | | no |
| LDAP_BIND_USER | | no |
| LDAP_BIND_PASSWORD | | no |

Ldap variables are mandatory to run services like Sync&Share.

### `vault-config.json` values

This variables are meant to be mandatory only if `FEATURE_VAULT_INTEGRATION=yes`.

_Although *TOKEN_TIME_DURATION and *TOKEN_RENEWAL_TIME_DURATION are both marked as mandatory they can be considered mutually exclusive._

| Key | Description | Mandatory |
| - | - | - |
| VAULT_URL | Vault service URL | yes |
| VAULT_ROLE | Vault role | yes |
| VAULT_OIDC_AUDIENCE | Vault registered audience for that role (**DEPRECATED**) | yes |
| VAULT_BOUND_AUDIENCE | Vault registered audience for that role | no |
| VAULT_SECRET_PATH | Root path for users secrets in URL (**DEPRECATED**) | no |
| VAULT_SECRETS_PATH | Root path for users secrets in URL *(currently not used in the code but only in the ansible receipt)* | no |
| WRAPPING_TOKEN_TIME_DURATION | | yes |
| READ_POLICY | Name of the read policy to use | yes |
| READ_TOKEN_TIME_DURATION | Vault token's delete permissions time duration | yes |
| READ_TOKEN_RENEWAL_TIME_DURATION | Periods for read token renewal. If this value is defined the token has time duration equals to the period. `READ_TOKEN_TIME_DURATION` can be omitted. | yes |
| WRITE_POLICY | Name of the write policy to use | yes |
| WRITE_TOKEN_TIME_DURATION | Vault token's write permissions time duration | yes |
| WRITE_TOKEN_RENEWAL_TIME_DURATION | Periods for write token renewal. If this value is defined the token has time duration equals to the period. `WRITE_TOKEN_TIME_DURATION` can be omitted. | yes |
| DELETE_POLICY | Name of the delete policy to use | yes |
| DELETE_TOKEN_TIME_DURATION | Vault token's delete permissions time duration | yes |
| DELETE_TOKEN_RENEWAL_TIME_DURATION | Periods for delete token renewal. If this value is defined the token has time duration equals to the period. `DELETE_TOKEN_TIME_DURATION` can be omitted. | yes |

# Run the application

> On dashboard first startup, from the **admin's settings** page, you will have to download the **tosca-templates** repository. This will be placed in the `TOSCA_TEMPLATES_DIR`.

> On dashboard first startup, from the **admin's settings** page, you will have to download the **dashboard-configuration** repository. This will be placed in the `SETTINGS_DIR`.

## Local environment

Command, to run the Flask application in your local environment

```bash=
FLASK_app=orchdashboard flask run --host=0.0.0.0 --cert cert.pem --key key.pem
```

Command to run the application using gunicorn in your local environment

```bash=
gunicorn -w 1 --timeout 60 \
    --bind 0.0.0.0:5000 \
    --certfile certs/cert.pem \
    --keyfile certs/key.pem \
    orchdashboard:app
```

Otherwise you can run the `docker/start.sh` script which is the script run at start up by the dockerized instances. 

This script use the `CERT` and `KEY` environment variables to define the path to the cert.pem and key.pem files; by default they are equals to `/certs/cert.pem` and `/certs/key.pem`. 

The port where to expose the service can be set using the `PORT` environment variable; by default, the `start.sh` script exposes the service on port **5001**.

To run the script:

```bash=
./docker/start.sh
```

## Dockerized environment

If you want to run the application in a docker container, the repository provides a docker image and a `docker-compose.yml` file to start all needed services. 

To run the docker container:

```bash=
docker run -d -p 5000:5001 \
    --name='orchestrator-dashboard' \
    -v $PWD/certs:/certs \
    -v $PWD/trusted_certs:/trusted_certs \
    -v $PWD/instance/:/app/instance/ \
    -e ENABLE_HTTPS=True \
    -e TOSCA_TEMPLATES_DIR=/app/instance/tosca-templates \
    -e SETTINGS_DIR=/app/instance/dashboard-configuration \
    -e UPLOAD_FOLDER=/app/instance/uploads \
    infn-datacloud/orchestrator-dashboard:latest
```

> Since you are running the application inside a container, remember to correctly set the `SQLALCHEMY_DATABASE_URI` and the `REDIS_URL` as environment variables or in the `config.json`.

In addition to the orchestrator-dashboard, the docker compose starts a 5.7 MySQL database and a redis service instance. Moveover it binds the `instance` folder in your project top directory. It expects to find all `.json` files in that directory and will place there the `tosca-templates`, the `dashboard-configuration` and the `uploads` folders. The `docker-compose.yml` correctly defines the environment variables `SQLALCHEMY_DATABASE_URI`, `REDIS_URL`, `TOSCA_TEMPLATES_DIR`, `SETTINGS_DIR` and `UPLOAD_FOLDER`.

To run the docker compose suite:

```bash=
docker compose -f docker/docker-compose.yml up -d
```

> By default, the docker image exposes port 5001 instead 5000. The `docker-compose.yml` maps port 5001 of the container to port 5000 of the localhost.
> By default `TOSCA_TEMPLATES_DIR`, `SETTINGS_DIR` and `UPLOAD_FOLDER` points to paths requiring administator rights. The `docker-compose.yml` maps those variables in user accessible paths.

## Devcontainer

For VSCode users, a devcontainer is present in the `.devcontainer` folder.

# How to build the docker image

```
git clone https://github.com/infn-datacloud/orchestrator-dashboard.git
cd orchestrator-dashboard
docker build -f docker/Dockerfile -t orchestrator-dashboard .
```

# Utilities

## TOSCA Template Metadata 

The Orchestrator dashboard can exploit some optional information provided in the TOSCA templates for rendering the cards describing the type of applications/services or virtual infrastructure that a user can deploy.

In particular, the following tags are supported:

| Tag name  | Description        | Type               |
| -------------- | ------------- | ------------------ |              
| description | Used for showing the card description  |  String |
| metadata.display_name | Used for the card title. If not pro  |    String |
| metadata.icon  |  Used for showing the card image. If no image URL is provided, the dashboard will load this [icon](https://cdn4.iconfinder.com/data/icons/mosaicon-04/512/websettings-512.png). | String |
| metadata.display_name | Used for the card title. If not provided, the template name will be used   | String |
| metadata.tag  | Used for the card ribbon (displayed on the right bottom corner)   |     String |
| metadata.allowed_groups | Used for showing the template only to members of specific groups |  String <br> - "*" == any group can see the template <br> - "group1,group2" == only members of _group1_ and _group2_ can see the template |

Example of template metadata:

```
tosca_definitions_version: tosca_simple_yaml_1_0

imports:
  - indigo_custom_types: https://raw.githubusercontent.com/indigo-dc/tosca-types/v4.0.0/custom_types.yaml

description: Deploy a Mesos Cluster (with Marathon and Chronos frameworks) on top of Virtual machines

metadata:
  display_name: Deploy a Mesos cluster
  icon: https://indigo-paas.cloud.ba.infn.it/public/images/apache-mesos-icon.png

topology_template:

....
```

## Using an HTTPS Proxy 

Example of configuration for nginx:

```
server {
    listen         80;
    server_name    YOUR_SERVER_NAME;
    return         301 https://$server_name$request_uri;
}

server {
    listen        443 ssl;
    server_name   YOUR_SERVER_NAME;
    access_log    /var/log/nginx/proxy-paas.access.log  combined;

    ssl on;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_certificate           /etc/nginx/cert.pem;
    ssl_certificate_key       /etc/nginx/key.pem;
    ssl_trusted_certificate   /etc/nginx/trusted_ca_cert.pem;

    location / {
        # Pass the request to Gunicorn
        proxy_pass http://127.0.0.1:5000/;

        proxy_set_header        X-Real-IP $remote_addr;
        proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto https;
        proxy_set_header        Host $http_host;
        proxy_redirect          http:// https://;
        proxy_buffering         off;
    }
}
```

## Add trusted certificates

If you need to install and trust certificates that are not included in the default CA bundle used by SLAT python application running in a docker container, you can mount the directory containing the cerficate(s) in PEM format (extensione .pem) in the container under the path /trusted_certs; e.g:

```
docker run -d -p 5001:5001 --name='orchestrator-dashboard' \
           -v $PWD/instance:/app/instance \
           -v $PWD/tosca-templates:/opt/tosca-templates \
           -v $PWD/trusted_certs:/trusted_certs \
           indigo-dc/orchestrator-dashboard:latest
```
The certificates provided in the directory will be automatically added to the python CA bundle.


## Performance tuning

You can change the number of gunicorn worker processes using the environment variable WORKERS.
E.g. if you want to use 2 workers, launch the container with the option `-e WORKERS=2`
Check the [documentation](http://docs.gunicorn.org/en/stable/design.html#how-many-workers) for ideas on tuning this parameter.

## Troubleshooting

### SSL Cert Verification
If you see problems with the SLAM interaction, you would need to specify the certificate to be used to verify the SSL connection.
You can pass the path to a CA_BUNDLE file or directory with certificates of trusted CAs setting the parameter SLAM_CERT in the config.json file:

```
{
  ...
  "SLAM_URL": "https://indigo-slam.cloud.ba.infn.it:8443",
  "SLAM_CERT": "/path/to/certfile"
}
```

If you are running the docker container, you need to ensure that the cert file is available inside the container in the path set in the SLAM_CERT parameter, i.e. you would use a bind mount (`-v $PWD/certfile:/path/to/cerfile`)

#### References:

- https://2.python-requests.org/en/master/user/advanced/#ssl-cert-verification
