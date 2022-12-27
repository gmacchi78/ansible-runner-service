from __future__ import annotations
import os
import shlex
import shutil
import socket
import sys
import getpass

from subprocess import Popen, PIPE
from threading import Timer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from OpenSSL import crypto


from runner_service import configuration

import logging
logger = logging.getLogger(__name__)


class RunnerServiceError(Exception):
    pass

def create_directory(dir_path):
    """ Create directory if it doesn't exist """
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

def fread(file_path):
    """ return the contents of the given file """
    with open(file_path, 'r') as file_fd:
        return file_fd.read().strip()


def create_self_signed_cert(cert_dir, cert_pfx):
    """
    Looks in cert_dir for the key files (using the cert_pfx name), and either
    returns if they exist, or create them if they're missing.
    """

    cert_filename = os.path.join(cert_dir,
                                 "{}.crt".format(cert_pfx))
    key_filename = os.path.join(cert_dir,
                                "{}.key".format(cert_pfx))

    logger.debug("Checking for the SSL keys in {}".format(cert_dir))
    if os.path.exists(cert_filename) \
            or os.path.exists(key_filename):
        logger.info("Using existing SSL files in {}".format(cert_dir))
        return (cert_filename, key_filename)
    else:
        logger.info("Existing SSL files not found in {}".format(cert_dir))
        logger.info("Self-signed cert will be created - expiring in {} "
                    "years".format(configuration.settings.cert_expiration))

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "North Carolina"
        cert.get_subject().L = "Raliegh"
        cert.get_subject().O = "Red Hat"         # noqa: E741
        cert.get_subject().OU = "Ansible"
        cert.get_subject().CN = socket.gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)

        # define cert expiration period(years)
        cert.gmtime_adj_notAfter(configuration.settings.cert_expiration * 365 * 24 * 60 * 60)   # noqa

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')

        # create cert_dir if it doesn't exist
        create_directory(cert_dir)

        logger.debug("Writing crt file to {}".format(cert_filename))
        with open(os.path.join(cert_dir, cert_filename), "wt") as cert_fd:
            cert_fd.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))   # noqa

        logger.debug("Writing key file to {}".format(key_filename))
        with open(os.path.join(cert_dir, key_filename), "wt") as key_fd:
            key_fd.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))    # noqa

        return (cert_filename, key_filename)


def rm_r(path):
    if not os.path.exists(path):
        return
    if os.path.isfile(path) or os.path.islink(path):
        os.unlink(path)
    else:
        shutil.rmtree(path)


def ssh_create_key(ssh_dir, user=None):

    if not user:
        user = getpass.getuser()

    prv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend())
    pub_key = prv_key.public_key()

    prv_file = os.path.join(ssh_dir, 'ssh_key')
    pub_file = os.path.join(ssh_dir, 'ssh_key.pub')

    # create ssh_dir if it doesn't exist
    create_directory(ssh_dir)

    # export the private key
    try:
        with open(prv_file, "wb") as f:
            f.write(prv_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()))

    except (OSError, IOError) as err:
        msg = "Unable to write to private key to '{}': {}".format(ssh_dir, err)
        logger.critical(msg)
        raise RunnerServiceError(msg)
    except Exception as err:
        logger.critical("Unknown error writing private key: {}".format(err))
        raise
    else:
        # python3 syntax
        os.chmod(prv_file, 0o600)
        logger.info("Created SSH private key @ '{}'".format(prv_file))

    # export the public key
    try:
        with open(pub_file, "wb") as f:
            f.write(pub_key.public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH))

    except (OSError, IOError) as err:
        msg = "Unable to write public ssh key to {}: {}".format(ssh_dir, err)
        logger.critical(msg)
        raise RunnerServiceError(msg)
    except Exception as err:
        logger.critical("Unknown error creating the public key "
                        "to {}: {}".format(ssh_dir, err))
        raise
    else:
        # python3 syntax
        os.chmod(pub_file, 0o644)
        logger.info("Created SSH public key @ '{}'".format(pub_file))


if sys.version_info[0] == 2:
    class ConnectionError(OSError):
        pass

    class ConnectionRefusedError(ConnectionError):
        pass


class HostNotFound(Exception):
    pass


class SSHNotAccessible(Exception):
    pass


class SSHTimeout(Exception):
    pass


class SSHIdentityFailure(Exception):
    pass


class SSHAuthFailure(Exception):
    pass


class SSHUnknownError(Exception):
    pass


class SSHClient(object):
    def __init__(self, user, host, identity, timeout=1, port=22):
        self.user = user
        self.port = port
        self.host = host
        self.timeout = timeout
        self.identity_file = identity

    def connect(self):

        def timeout_handler():
            proc.kill()
            raise SSHTimeout

        socket.setdefaulttimeout(self.timeout)
        try:
            family, *_, sockaddr = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM, socket.SOL_TCP)[0]
        except socket.gaierror:
            raise HostNotFound

        with socket.socket(family, socket.SOCK_STREAM, socket.SOL_TCP) as s:
            try:
                s.connect(sockaddr)
            except ConnectionRefusedError:
                raise SSHNotAccessible
            except socket.timeout:
                raise SSHTimeout
            else:
                s.shutdown(socket.SHUT_RDWR)

        # Now try and use the identity file to passwordless ssh
        cmd = ('ssh -o "StrictHostKeyChecking=no" '
               '-o "IdentitiesOnly=yes" '
               ' -o "PasswordAuthentication=no" '
               ' -i {} '
               '{}@{} python --version'.format(self.identity_file, self.user, self.host))

        proc = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
        timer = Timer(self.timeout, timeout_handler)
        try:
            timer.start()
            stdout, stderr = proc.communicate()
        except Exception as e:
            raise SSHUnknownError(e)
        else:
            if 'permission denied' in stderr.decode().lower():
                raise SSHAuthFailure(stderr)
        finally:
            timer.cancel()


def ssh_connect_ok(host, user=None, port=None):

    if not user:
        if configuration.settings.target_user:
            user = configuration.settings.target_user
        else:
            user = getpass.getuser()

    priv_key = os.path.join(configuration.settings.ssh_private_key)

    if not os.path.exists(priv_key):
        return False, "FAILED:SSH key(s) missing from ansible-runner-service"

    target = SSHClient(
        user=user,
        host=host,
        identity=priv_key,
        timeout=configuration.settings.ssh_timeout,
        port=22 if port is None else port,
    )

    try:
        target.connect()
    except HostNotFound:
        return False, "NOCONN:SSH error - '{}' not found; check DNS or " \
                "/etc/hosts".format(host)
    except SSHNotAccessible:
        return False, "NOCONN:SSH target '{}' not contactable; host offline" \
                      ", port 22 blocked, sshd running?".format(host)
    except SSHTimeout:
        return False, "TIMEOUT:SSH timeout waiting for response from " \
                      "'{}'".format(host)
    except SSHAuthFailure:
        return False, "NOAUTH:SSH auth error - passwordless ssh not " \
            "configured for '{}'".format(host)
    else:
        return True, "OK:SSH connection check to {} successful".format(host)


from dataclasses import dataclass
@dataclass(frozen=True)
class User:

    name: str
    expired: bool

class InvalidUserException(Exception):
    pass

import random
import string
import sqlite3
from sqlite3 import Error
import bcrypt
from typing import List
class SecureContext:

    
    def __init__(self, ctx:str) -> None:
        self.ctx=ctx
        pass

    def _create_password()->str:
        letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
        result_str = ''.join(random.choice(letters) for i in range(10))
        return result_str

    def _execute(database: str, statement:str, params:tuple=None)->None:
        conn = None
        try:
            conn = sqlite3.connect(database)
            cur = conn.cursor()
            if params is not None:
                cur.execute(statement,params)
            else:
                cur.execute(statement)
            conn.commit()
        except Error as e:
            print(e)
            raise e
        finally:
            if conn is not None:
                conn.close()

    def _query(database: str, statement:str, params:tuple=None)->List[tuple]:
        conn = None
        try:
            conn = sqlite3.connect(database)
            cur = conn.cursor()
            res = None
            if params is not None:
                res = cur.execute(statement,params)
            else:
                res = cur.execute(statement)
            return res.fetchall()
        except Error as e:
            print(e)
            raise e
        finally:
            if conn is not None:
                conn.close()

    def _create_database(database: str, admin_passwd:str)->None:
        SecureContext._execute(database=database, statement="CREATE TABLE user(name TEXT PRIMARY KEY, password TEXT NOT NULL, expired INT NOT NULL)")
        hashed = bcrypt.hashpw(admin_passwd.encode('utf-8'), bcrypt.gensalt())
        SecureContext._execute(database=database, 
            statement=f"INSERT INTO user (name,password, expired) VALUES (?, ?, ?)", 
            params=('admin',hashed.decode('utf-8'),1))
        
        
        os.chmod(database, 0o600)

    def get_or_create(dir:str=None)->SecureContext:
        if dir is None:
            dir = configuration.settings.config_dir
        database = os.path.join(dir, "users.db")
        if os.path.exists(database):
            return SecureContext(database)
        else:
            tmp_cred = SecureContext._create_password()
            logger.info(f"Creating temporary admin credentials as {tmp_cred}")
            SecureContext._create_database(database, tmp_cred)
            return SecureContext(database)

    def get_user(self, user_name:str, passwd:str)->User:
        res = SecureContext._query(self.ctx,"SELECT password, expired FROM user WHERE name = ? LIMIT 1", (user_name,))
        if res is None or len(res)==0:
            raise InvalidUserException
        hashed = res[0][0]
        if bcrypt.checkpw(passwd.encode('utf-8'), hashed.encode('utf-8')):
            return User(name=user_name, expired=res[0][1]==1)
        raise InvalidUserException

    def update_password(self, user_name:str, old_passwd:str, new_passwd:str)->User:
        self.get_user(
            user_name=user_name, passwd=old_passwd
        )
        hashed = bcrypt.hashpw(new_passwd.encode('utf-8'), bcrypt.gensalt())
        SecureContext._execute(database=self.ctx, 
            statement=f"UPDATE user set password = ?, expired=0 WHERE name = ?", 
            params=(hashed.decode('utf-8'),'admin'))
        return self.get_user(
            user_name=user_name, passwd=new_passwd
        )


from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

@auth.verify_password
def verify(username, password):
    if not (username and password):
        return False
    sc = SecureContext.get_or_create()
    user:User = None
    try:
        user = sc.get_user(user_name=username, passwd=password)
    except InvalidUserException:
        logger.error("Invalid username or password")
        return False
    if user.expired:
        logger.error(f"Password expired for user {username}")
        return False
    return True
