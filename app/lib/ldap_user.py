# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2020
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random,os,hashlib
import ldap,ldap.modlist
from . import VaultClient


class Error(Exception):
    """Base class for exceptions"""
    pass

class AlreadyExistingError(Error):

    def __init__(self, username, email):
        message = "Cannot retrieve stored info for existing ldap user {} with email {}".format(username, email)
        self.message = message
        super().__init__(message)

class PasswordMismatch(Error):
    def __init__(self, username, email):
        message = "Password changed for existing ldap user {} with email {}".format(username, email)
        self.message = message
        super().__init__(message)

class LdapUserManager(object):

    def __init__(self, ldapsocket, ldapcacert, ldapbase, binduser, bindpw, secretstore : VaultClient):

        self.ldapsocket = ldapsocket
        self.ldapbase = ldapbase
        self.binduser = "uid={},{}".format(binduser,self.ldapbase)
        self.bindpw = bindpw

        if(ldapcacert):
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ldapcacert)

        # bind
        self.l = ldap.initialize(ldapsocket)
        self.l.bind(self.binduser, self.bindpw)
        self.vault = secretstore


    def get_users(self):
        r = self.l.search_s(self.ldapbase, ldap.SCOPE_SUBTREE, 'uid=*')
        existingusers = []
        for i in r:
            d = i[1]
            uid = d['uid'][0]
            existingusers.append(uid)
        return existingusers

    def create_user(self, username, email):

        existingusers = self.get_users()

        pw = ""
        if username.encode('UTF-8') in existingusers:
            #read the credentials from vault
            user = self.vault.v1_read_secret('ldap_user')

            if user is None:
                raise AlreadyExistingError(username, email)

            if not self.verify_password(user['data']['username'], user['data']['password']):
                raise PasswordMismatch(username, email)

            pw = user['data']['password']

        else:

            (pw, hpw) = pwgen()
            dn = "uid={},{}".format(username, self.ldapbase)
            uid = username.encode('UTF-8')
            modlist = {"objectClass": [b"inetOrgPerson"], "uid": [uid], "mail": [email.encode('UTF-8')],
                       'userPassword': [hpw.encode('UTF-8')], 'sn': [uid], 'givenName': uid, 'cn': uid}
            r = self.l.add_s(dn, ldap.modlist.addModlist(modlist))

            # store credentials in vault
            self.vault.v1_write_secret('ldap_user', {"username": username, "password": pw})

        return username, pw

    def reset_password(self, username):
        (pw,hpw) = pwgen()
        dn = "uid={},{}".format(username, self.ldapbase)
        modList = [(ldap.MOD_REPLACE,'userPassword',hpw.encode('UTF-8'))]
        rr = self.l.modify_s(dn,modList)
        return pw

    def verify_password(self, username, password):
        pw = password.encode('UTF-8')
        query = "uid={}".format(username)
        result = self.l.search_s(self.ldapbase,ldap.SCOPE_SUBTREE, query)
        cpw = result[0][1]['userPassword'][0]

        return pwverify(cpw,pw)



def pwgen():
    #generate password
    chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pw = ''.join(random.choice(chars) for i in range(10)) # clear password
    # use SSHA = seeded SHA1
    #return (pw.decode('UTF-8'),"{SSHA}" + encode(h.digest() + salt).decode('UTF-8'))
    hpw = pw
    return (pw,hpw)


def pwverify(cpw, pw):
    return pw == cpw
