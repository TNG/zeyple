#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import logging
import email
import email.mime.multipart
import email.mime.application
from email.mime.text import MIMEText
import email.encoders
import smtplib
import copy
from io import BytesIO
import re
from subprocess import Popen, PIPE


MISSING_KEY_RULES_SECTION = 'missing_key_rules'

ACTION_DROP = 'drop'
ACTION_NOTIFY = 'notify'
ACTION_CLEARTEXT = 'cleartext'

VALID_ACTIONS = [
  ACTION_DROP,
  ACTION_NOTIFY,
  ACTION_CLEARTEXT,
]

DEFAULT_MISSING_KEY_NOTIFICATION = """
Hello,

the sender of this message tried to encrypt a message for you
with PGP using a Zeyple encryption gateway. Unfortunately that
failed. Zeyple was configured to drop the message for security
reasons. If you supply your PGP public key to the sender, you
may have better luck next time.

Sorry
Your Zeyple
"""


try:
    from configparser import ConfigParser  # Python 3
except ImportError:
    from ConfigParser import ConfigParser  # Python 2

legacy_gpg = False
try:
    import gpg
except ImportError:
    import gpgme
    legacy_gpg = True

# Boiler plate to avoid dependency on six
# BBB: Python 2.7 support
PY3K = sys.version_info > (3, 0)


def message_from_binary(message):
    if PY3K:
        return email.message_from_bytes(message)
    else:
        return email.message_from_string(message)


def as_binary_string(email):
    if PY3K:
        return email.as_bytes()
    else:
        return email.as_string()


def encode_string(string):
    if isinstance(string, bytes):
        return string
    else:
        return string.encode('utf-8')


__title__ = 'Zeyple'
__version__ = '1.2.2'
__author__ = 'Cédric Félizard'
__license__ = 'AGPLv3+'
__copyright__ = 'Copyright 2012-2018 Cédric Félizard'


def get_config_from_file_handle(handle):
    config = ConfigParser()
    if sys.version_info >= (3, 2):
        config.read_file(handle)
    else:
        config.readfp(handle)
    if not config.sections():
        raise IOError('Cannot open config file.')

    if config.has_option('zeyple', 'missing_key_notification_file'):
        file_name = config.get('zeyple', 'missing_key_notification_file')
        with open(file_name) as fh:
            config.missing_key_notification_body = fh.read()
    elif not config.has_option('zeyple', 'missing_key_notification_body'):
        config.missing_key_notification_body = \
            DEFAULT_MISSING_KEY_NOTIFICATION
    return config


def init_logging(config):
    log_file = config.get('zeyple', 'log_file')
    logging.basicConfig(
        filename=log_file, level=logging.DEBUG,
        format='%(asctime)s %(process)s %(levelname)s %(message)s'
    )


class NoUsableKeyException(Exception):
    pass


class Zeyple:
    def __init__(self, config, smtp_wrapper, gpg_manager, missing_key_oracle):
        self.config = config
        self._smtp_wrapper = smtp_wrapper
        self._missing_key_oracle = missing_key_oracle
        self._gpg_wrapper = gpg_manager
        self.sent_messages = []
        logging.info("Zeyple ready to encrypt outgoing emails")

    def process_message(self, message_data, recipients):
        message_data = encode_string(message_data)
        in_message = message_from_binary(message_data)
        logging.info(
            "Processing outgoing message %s", in_message['Message-id']
        )
        if not recipients:
            logging.warn("Cannot find any recipients, ignoring")

        self.sent_messages = []
        for recipient in recipients:
            self._process_message_for_recipient(in_message, recipient)

    def _process_message_for_recipient(self, in_message, recipient):
        try:
            logging.info("Recipient: %s", recipient)
            out_message = self._gpg_wrapper.get_encryted_message(
                in_message, recipient
            )
            self._smtp_wrapper.send(out_message, recipient)
        except NoUsableKeyException as e:
            self._handle_no_usable_key(in_message, recipient, str(e))

    def _handle_no_usable_key(self, in_message, recipient, message):
        action = self._missing_key_oracle.get_action(recipient)
        if action == ACTION_DROP:
            logging.error("{0}, message will not be sent!".format(message))
        elif action == ACTION_CLEARTEXT:
            logging.warning(
                "{0}, message will be sent unencrypted".format(message)
            )
            self._smtp_wrapper.send(copy.copy(in_message), recipient)
        else:
            logging.warning(
                "{0}, sending notification to recipient".format(message),
            )
            self._smtp_wrapper.send(
                self._get_missing_key_message(in_message, recipient),
                recipient
            )

    def _get_missing_key_message(self, in_message, recipient):
        out_message = MIMEText(
            self.config.missing_key_notification_body, 'plain', 'utf-8'
        )
        if self.config.has_option(
            'zeyple', 'missing_key_notification_subject'
        ):
            out_message['Subject'] = self.config.get(
                'zeyple', 'missing_key_notification_subject'
            )
        else:
            out_message['Subject'] = 'Missing PGP key'
        out_message['To'] = recipient
        out_message['From'] = in_message['From']
        return out_message


class SmtpWrapper:
    def __init__(self, config):
        self._relay_host = config.get('relay', 'host')
        self._relay_port = config.getint('relay', 'port')
        if config.has_option('zeyple', 'add_header'):
            self._add_header = config.getboolean('zeyple', 'add_header')
        else:
            self._add_header = False

    def send(self, message, recipient):
        logging.info("Sending message %s", message['Message-id'])

        if self._add_header:
            message.add_header(
                'X-Zeyple',
                "processed by {0} v{1}".format(__title__, __version__)
            )

        smtp = smtplib.SMTP(self._relay_host, self._relay_port)
        smtp.sendmail(message['From'], recipient, message.as_string())
        smtp.quit()

        logging.info("Message %s sent", message['Message-id'])


class _GpgGroupMapper:
    """
    This code is heavily inspire by groups.py script found some version of
    gpgme. Big thanks to those guys to point out the right way (and only
    minor curses for not supporting GPG groups out-of-the-box.)
    """
    def __init__(self, config):
        self._key_ids_by_group = {}
        self._gpg_home = config.get('gpg', 'home')
        self._key_ids_by_group = {}
        if config is not None:
            self.load_group_mapping()

    def load_group_mapping(self):
        logging.info('Loading groups from GPG configuration')
        self._key_ids_by_group = {}
        raw_data = self._get_group_data()
        if raw_data is None:
            logging.info('No group data found.')
            return
        for item in raw_data.split(','):
            self._process_config_item(item)
        logging.info(
            "Loaded data for {0} groups.".format(len(self._key_ids_by_group))
        )

    def _get_group_data(self):
        if sys.platform == "win32":
            gpgconf_command = 'gpgconf.exe'
        else:
            gpgconf_command = 'gpgconf'
        process = Popen([
                gpgconf_command,
                '--homedir', self._gpg_home,   # that seems not to work!
                '--list-options', 'gpg'
            ],
            stdout=PIPE,
            env={'GNUPGHOME': self._gpg_home}  # Workaround
        )
        raw_result = process.communicate()[0]
        if sys.version_info[0] == 3:
            cooked_result = raw_result.decode()
        else:
            cooked_result = raw_result
        for line in cooked_result.splitlines():
            if line.startswith("group"):
                return line.split(":")[-1]
        return None

    def _process_config_item(self, item):
        if item is None or item == '':
            return
        raw_email, key_id = item.split('=')
        cooked_email = raw_email.lstrip('"<').rstrip('>')
        if cooked_email not in self._key_ids_by_group:
            self._key_ids_by_group[cooked_email] = [key_id]
        else:
            self._key_ids_by_group[cooked_email].append(key_id)

    def exists(self, email):
        return email in self._key_ids_by_group

    def get_key_ids_for_group(self, email):
        return self._key_ids_by_group[email]


class GpgManager:
    def __init__(self, config):
        self._ctx = None
        self._group_mapper = None
        if config is not None:
            self.setup(config)
            self._group_mapper = _GpgGroupMapper(config)

    def setup(self, config):
        global legacy_gpg
        if legacy_gpg:
            protocol = gpgme.PROTOCOL_OpenPGP
            self._ctx = gpgme.Context()
        else:
            protocol = gpg.constants.PROTOCOL_OpenPGP
            self._ctx = gpg.Context()
        if config.has_option('gpg', 'executable'):
            executable = config.get('gpg', 'executable')
        else:
            executable = None  # Default value
        gpg_home = config.get('gpg', 'home')

        self._ctx.set_engine_info(protocol, executable, gpg_home)
        self._ctx.armor = True

    def get_encryted_message(self, in_message, recipient):
        logging.info("Trying to encrypt for %s", recipient)
        gpg_keys = self.get_keys_for_recipient(recipient)
        if in_message.is_multipart():
            payload = self._get_payload_from_multipart_message(in_message)
        else:
            payload = self._get_payload_from_simple_message(in_message)

        encrypted_payload = self.encrypt_payload(payload, gpg_keys)
        version = self._get_version_part()
        encrypted = self._get_encrypted_part(encrypted_payload)

        out_message = copy.copy(in_message)
        out_message.preamble = "This is an OpenPGP/MIME encrypted " \
                               "message (RFC 4880 and 3156)"

        if 'Content-Type' not in out_message:
            out_message['Content-Type'] = 'multipart/encrypted'
        else:
            out_message.replace_header(
                'Content-Type',
                'multipart/encrypted',
            )
        del out_message['Content-Transfer-Encoding']
        out_message.set_param('protocol', 'application/pgp-encrypted')
        out_message.set_payload([version, encrypted])

        return out_message

    def get_keys_for_recipient(self, recipient):
        if self._group_mapper.exists(recipient):
            return [
                self.get_key_by_id(key_id)
                for key_id in self._group_mapper.get_key_ids_for_group(
                    recipient
                )
            ]
        else:
            return [self._get_key_for_simple_email_address(recipient)]

    def _get_key_for_simple_email_address(self, recipient):
        # Explicit matching of email and uid.email necessary.
        # Otherwise gpg.keylist will return a list of keys
        # for searches like "n"
        for key in self._ctx.keylist(recipient):
            if not self._validate_uid(key, recipient):
                continue
            sub_key = self._try_to_find_valid_sub_key(key)
            if sub_key is not None:
                return sub_key
        raise NoUsableKeyException(
            "Failed to find key for {0}".format(recipient)
        )

    def _validate_uid(self, key, recipient):
        normalized_recipient = recipient.lower()
        for uid in key.uids:
            normalized_uid = uid.email.lower()
            if normalized_recipient == normalized_uid:
                return True
        return False

    def _try_to_find_valid_sub_key(self, key):
        for sub_key in key.subkeys:
            key_id = key.subkeys[0].keyid
            gpg_key = self.get_key_by_id(key_id)
            if gpg_key.expired:
                logging.info("Ignoring expired key {0}".format(key_id))
                continue
            if gpg_key.revoked:
                logging.info("Ignoring revoked key {0}".format(key_id))
                continue
            if gpg_key.invalid:
                logging.info("Ignoring invalid key {0}".format(key_id))
                continue
            if not gpg_key.can_encrypt:
                logging.info(
                    "Ignoring key {0} not suitable for encryption".format(
                        key_id
                    )
                )
                continue
            return gpg_key
        return None

    def get_key_by_id(self, key_id):
        return self._ctx.get_key(key_id)

    def _get_payload_from_multipart_message(self, in_message):
        body = in_message.as_string().split("\n\n", 1)[1].strip()
        header = "Content-Type: " + in_message["Content-Type"]

        payload = header + "\n\n" + body

        message = email.message.Message()
        message.set_payload(payload)
        return message.get_payload()

    def _get_payload_from_simple_message(self, in_message):
        message = email.mime.nonmultipart.MIMENonMultipart(
            in_message.get_content_maintype(),
            in_message.get_content_subtype()
        )
        payload = encode_string(in_message.get_payload())
        message.set_payload(payload)

        # list of additional parameters in content-type
        params = in_message.get_params()
        if params:
            # first item is the main/sub type so discard it
            del params[0]
            for param, value in params:
                message.set_param(param, value, "Content-Type", False)

        encoding = in_message["Content-Transfer-Encoding"]
        if encoding:
            message.add_header("Content-Transfer-Encoding", encoding)

        del message['MIME-Version']

        mixed = email.mime.multipart.MIMEMultipart(
            'mixed',
            None,
            [message],
        )

        # remove superfluous header
        del mixed['MIME-Version']
        return as_binary_string(mixed)

    def _get_version_part(self):
        ret = email.mime.application.MIMEApplication(
            'Version: 1\n',
            'pgp-encrypted',
            email.encoders.encode_noop,
        )
        ret.add_header(
            'Content-Description',
            "PGP/MIME version identification",
        )
        del ret['MIME-Version']
        return ret

    def _get_encrypted_part(self, payload):
        ret = email.mime.application.MIMEApplication(
            payload,
            'octet-stream',
            email.encoders.encode_noop,
            name="encrypted.asc",
        )
        ret.add_header('Content-Description', "OpenPGP encrypted message")
        ret.add_header(
            'Content-Disposition',
            'inline',
            filename='encrypted.asc',
        )
        del ret['MIME-Version']
        return ret

    def encrypt_payload(self, payload, gpg_keys):
        global legacy_gpg
        payload = encode_string(payload)
        self._ctx.armor = True

        if legacy_gpg:
            plaintext = BytesIO(payload)
            ciphertext = BytesIO()
            self._ctx.encrypt(
                gpg_keys, gpgme.ENCRYPT_ALWAYS_TRUST,
                plaintext, ciphertext
            )
            return ciphertext.getvalue()
        else:
            (ciphertext, encresult, signresult) = self._ctx.encrypt(
                gpg.Data(string=payload),
                recipients=gpg_keys,
                sign=False,
                always_trust=True
            )
            return ciphertext


class _ActionRule:
    def __init__(self, pattern, action):
        if action not in VALID_ACTIONS:
            logging.error(
                "Pattern '{0}' has bad action! Must be one of: {1}".format(
                    pattern, ', '.join(VALID_ACTIONS)
                )
            )
        self.pattern = re.compile(pattern)
        self.action = action

    def check(self, email):
        if self.pattern.match(email):
            return self.action
        else:
            return None


class MissingKeyOracle:
    def __init__(self, config=None):
        self._rules = []
        if config is not None:
            self.load_configuration(config)

    def load_configuration(self, config):
        if config.has_section(MISSING_KEY_RULES_SECTION):
            for option in config.options(MISSING_KEY_RULES_SECTION):
                value = config.get(MISSING_KEY_RULES_SECTION, option)
                self._rules.append(_ActionRule(option, value))

        if config.has_option('zeyple', 'force_encrypt'):
            logging.warning(
                'Found deprecated configuration parameter force_encrypt!'
            )
            logging.warning(
                'Please use a [{0}] section instead.'.format(
                    MISSING_KEY_RULES_SECTION
                )
            )
            if config.getboolean('zeyple', 'force_encrypt'):
                action = ACTION_DROP
            else:
                action = ACTION_CLEARTEXT
            logging.warning(
                "The entry '. = {0}' will do what you want.".format(action)
            )
            self._rules.append(_ActionRule('.', action))

    def get_action(self, email):
        for rule in self._rules:
            action = rule.check(email)
            if action is not None:
                return action
        return ACTION_NOTIFY


if __name__ == '__main__':
    recipients = sys.argv[1:]

    # BBB: Python 2.7 support
    binary_stdin = sys.stdin.buffer if PY3K else sys.stdin
    message = binary_stdin.read()

    with open('/etc/zeyple.conf') as handle:
        config = get_config_from_file_handle(handle)
    init_logging(config)
    zeyple = Zeyple(
        config,
        smtp_wrapper=SmtpWrapper(config),
        gpg_manager=GpgManager(config),
        missing_key_oracle=MissingKeyOracle(config)
    )
    zeyple.process_message(message, recipients)
