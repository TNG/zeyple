#!/usr/bin/env python
# -*- coding: utf-8 -*-

# BBB: Python 2.7 support
from __future__ import unicode_literals

import unittest
import pytest
import os
import sys
import subprocess
import shutil
import re
import tempfile
from textwrap import dedent
from io import StringIO
from zeyple.zeyple import Zeyple, get_config_from_file_handle, GpgManager, MissingKeyOracle, NoUsableKeyException

legacy_gpg = False
try:
    import gpg
except ImportError:
    import gpgme
    legacy_gpg = True

KEYS_FNAME = os.path.join(os.path.dirname(__file__), 'keys.gpg')
TEST1_ID = 'D6513C04E24C1F83'
TEST1_EMAIL = 'test1@zeyple.example.com'
TEST2_ID = '0422F1C597FB1687'
TEST2_EMAIL = 'test2@zeyple.example.com'
TEST_GROUP = 'all@zeyple.example.com'
TEST_EXPIRED_ID = 'ED97E21F1C7F1AC6'
TEST_EXPIRED_EMAIL = 'test_expired@zeyple.example.com'
ERNO_VALID_SUBKEY_ID = '9349176209663454'

GPG_CONF_CONTENT = """
group <{0}>={1}
group <{0}>={2}
""".format(TEST_GROUP, TEST1_ID, TEST2_ID)

DEFAULT_CONFIG_TEMPLATE = """
[gpg]
home = {0}

[relay]
host = example.net
port = 2525

[zeyple]
log_file = {1}
add_header = true
"""


def get_test_email():
    filename = os.path.join(os.path.dirname(__file__), 'test.eml')
    with open(filename, 'r') as test_file:
        return test_file.read()


def write_file(name, content, encoding='utf-8'):
    if sys.version_info >= (3, 0):
        with open(name, 'w', encoding=encoding) as out:
            out.write(content)
    else:
        with open(name, 'w') as out:
            out.write(content.encode(encoding))


class SmtpWrapperMock:
    def __init__(self):
        self.sent_messages = []

    def send(self, message, recipient):
        self.sent_messages.append({
            'message': message,
            'envelop_to': recipient
        })


class ZeypleTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

        self.conffile = os.path.join(self.tmpdir, 'zeyple.conf')
        self.homedir = os.path.join(self.tmpdir, 'gpg')
        self.logfile = os.path.join(self.tmpdir, 'zeyple.log')
        self.smtp_wrapper = SmtpWrapperMock()

        os.mkdir(self.homedir, 0o700)
        subprocess.check_call(
            ['gpg', '--homedir', self.homedir, '--import', KEYS_FNAME],
            stderr=open('/dev/null'),
        )

    def get_config(self, config_template=None):
        if config_template is None:
            config_template = DEFAULT_CONFIG_TEMPLATE
        config_text = config_template.format(self.homedir, self.logfile)
        handle = StringIO(config_text)
        return get_config_from_file_handle(handle)

    def get_zeyple(self, config_template=None):
        self.smtp_wrapper.sent_messages = []
        config = self.get_config(config_template)
        return Zeyple(
            config=config,
            smtp_wrapper=self.smtp_wrapper,
            gpg_manager=GpgManager(config),
            missing_key_oracle=MissingKeyOracle(config)
        )

    def get_gpg_manager(self, config_template=None):
        config = self.get_config(config_template)
        return GpgManager(config)

    def assert_message_count(self, count):
        assert len(self.smtp_wrapper.sent_messages) == count

    def message(self, index):
        return self.smtp_wrapper.sent_messages[index]['message']

    def assert_message_header(self, index, header, value):
        assert self.message(index)[header] == value

    def get_payload(self, index):
        return self.message(index).get_payload(decode=True).decode('utf-8')

    def assert_envelop_to(self, index, value):
        assert self.smtp_wrapper.sent_messages[index]['envelop_to'] == value

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def decrypt(self, data):
        gpg = subprocess.Popen(
            ['gpg', '--homedir', self.homedir, '--decrypt'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        return gpg.communicate(data)[0]

    def assert_valid_mime_message(self, index, orig_message):
        cipher_message = self.message(index)
        assert cipher_message.is_multipart()

        plain_payload = cipher_message.get_payload()
        encrypted_envelope = plain_payload[1]
        assert encrypted_envelope["Content-Type"] == 'application/octet-stream; name="encrypted.asc"'

        encrypted_payload = encrypted_envelope.get_payload().encode('utf-8')
        decrypted_payload = self.decrypt(encrypted_payload).decode('utf-8').strip()

        boundary = re.match(r'.+boundary="([^"]+)"', decrypted_payload, re.MULTILINE | re.DOTALL).group(1)
        # replace auto-generated boundary with one we know
        orig_message = orig_message.replace("BOUNDARY", boundary)

        prefix = dedent("""\
            Content-Type: multipart/mixed; boundary=\"""" + \
            boundary + """\"

            """)
        orig_message = prefix + orig_message

        assert decrypted_payload == orig_message

    def test_user_key(self):
        """Returns the right ID for the given email address"""

        gpg_manager = self.get_gpg_manager()
        with pytest.raises(NoUsableKeyException):
            gpg_manager.get_keys_for_recipient('non_existant@example.org')

        user_keys = gpg_manager.get_keys_for_recipient(TEST1_EMAIL)
        assert len(user_keys) == 1
        assert user_keys[0].subkeys[0].keyid == TEST1_ID

        user_key = gpg_manager.get_keys_for_recipient(TEST1_EMAIL.upper())
        assert len(user_keys) == 1
        assert user_keys[0].subkeys[0].keyid == TEST1_ID

    def test_user_subkeys(self):
        """Returns only keys with valid subkeys"""

        gpg_manager = self.get_gpg_manager()
        with pytest.raises(NoUsableKeyException):
            gpg_manager.get_keys_for_recipient('erno.subkey@example.com')

        user_keys = gpg_manager.get_keys_for_recipient('erno.valid_subkey@example.com')
        assert len(user_keys) == 1
        assert user_keys[0].subkeys[0].keyid == ERNO_VALID_SUBKEY_ID

    def test_encrypt_with_plain_text(self):
        """Encrypts plain text"""
        content = 'The key is under the carpet.'.encode('ascii')
        gpg_manager = self.get_gpg_manager()
        gpg_key = gpg_manager.get_key_by_id(TEST1_ID)
        encrypted = gpg_manager.encrypt_payload(content, [gpg_key])
        assert self.decrypt(encrypted) == content

    def test_expired_key(self):
        zeyple = self.get_zeyple()

        # Expired keys are now just like missing keys
        zeyple.process_message(get_test_email(), [TEST_EXPIRED_EMAIL])

        self.assert_message_count(1)
        self.assert_message_header(0, 'Subject', 'Missing PGP key')

    def test_encrypt_binary_data(self):
        """Encrypts utf-8 characters"""
        content = b'\xc3\xa4 \xc3\xb6 \xc3\xbc'
        gpg_manager = self.get_gpg_manager()
        gpg_key = gpg_manager.get_key_by_id(TEST1_ID)
        encrypted = gpg_manager.encrypt_payload(content, [gpg_key])
        assert self.decrypt(encrypted) == content

    def test_process_message_with_simple_message(self):
        """Encrypts simple messages"""

        mime_message = dedent("""\
            --BOUNDARY
            Content-Type: text/plain

            test
            --BOUNDARY--""")

        self.get_zeyple().process_message(dedent("""\
            Received: by example.org (Postfix, from userid 0)
                id DD3B67981178; Thu,  6 Sep 2012 23:35:37 +0000 (UTC)
            To: """ + TEST1_EMAIL + """
            Subject: Hello
            Message-Id: <20120906233537.DD3B67981178@example.org>
            Date: Thu,  6 Sep 2012 23:35:37 +0000 (UTC)
            From: root@example.org (root)

            test""").encode('ascii'), [TEST1_EMAIL])

        self.assert_valid_mime_message(0, mime_message)

    def test_process_message_with_unicode_message(self):
        """Encrypts unicode messages"""

        mime_message = dedent("""\
            --BOUNDARY
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: 8bit

            ä ö ü
            --BOUNDARY--""")

        self.get_zeyple().process_message(dedent("""\
            Received: by example.org (Postfix, from userid 0)
                id DD3B67981178; Thu,  6 Sep 2012 23:35:37 +0000 (UTC)
            To: """ + TEST1_EMAIL + """
            Subject: Hello
            Message-Id: <20120906233537.DD3B67981178@example.org>
            Date: Thu,  6 Sep 2012 23:35:37 +0000 (UTC)
            From: root@example.org (root)
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: 8bit

            ä ö ü""").encode('utf-8'), [TEST1_EMAIL])

        self.assert_valid_mime_message(0, mime_message)

    def test_process_message_with_multipart_message(self):
        """Encrypts multipart messages"""

        mime_message = dedent("""\
            This is a multi-part message in MIME format

            --BOUNDARY
            Content-Type: text/plain; charset=us-ascii
            Content-Transfer-Encoding: 7bit
            Content-Disposition: inline

            test

            --BOUNDARY
            Content-Type: application/x-sh
            Content-Transfer-Encoding: base64
            Content-Disposition: attachment;
             filename="trac.sh"

            c3UgLWMgJ3RyYWNkIC0taG9zdG5hbWUgMTI3LjAuMC4xIC0tcG9ydCA4MDAwIC92YXIvdHJh
            Yy90ZXN0JyB3d3ctZGF0YQo=
            --BOUNDARY--""")

        self.get_zeyple().process_message((dedent("""\
            Return-Path: <torvalds@linux-foundation.org>
            Received: by example.org (Postfix, from userid 0)
                id CE9876C78258; Sat,  8 Sep 2012 13:00:18 +0000 (UTC)
            Date: Sat, 08 Sep 2012 13:00:18 +0000
            To: """ + TEST1_EMAIL + ', ' + TEST2_EMAIL + """
            Subject: test
            User-Agent: Heirloom mailx 12.4 7/29/08
            MIME-Version: 1.0
            Content-Type: multipart/mixed; boundary="BOUNDARY"
            Message-Id: <20120908130018.CE9876C78258@example.org>
            From: root@example.org (root)

        """) + mime_message).encode('ascii'), [TEST1_EMAIL, TEST2_EMAIL])

        self.assert_valid_mime_message(0, mime_message)
        self.assert_valid_mime_message(1, mime_message)

    def test_process_message_with_multiple_recipients(self):
        """Encrypt a message with multiple recipients"""

        emails = self.get_zeyple().process_message(dedent("""\
            Received: by example.org (Postfix, from userid 0)
                id DD3B67981178; Thu,  6 Sep 2012 23:35:37 +0000 (UTC)
            To: """ + ', '.join([TEST1_EMAIL, TEST2_EMAIL]) + """
            Subject: Hello
            Message-Id: <20120906233537.DD3B67981178@example.org>
            Date: Thu,  6 Sep 2012 23:35:37 +0000 (UTC)
            From: root@example.org (root)

            hello""").encode('ascii'), [TEST1_EMAIL, TEST2_EMAIL])

        self.assert_message_count(2)
        self.assert_envelop_to(0, TEST1_EMAIL)
        self.assert_envelop_to(1, TEST2_EMAIL)

    def test_process_message_with_complex_message(self):
        """Encrypts complex messages"""
        contents = get_test_email()
        self.get_zeyple().process_message(contents, [TEST1_EMAIL]) # should not raise

    def test_force_encryption_deprecated(self):
        """Tries to encrypt without key"""
        contents = get_test_email()
        zeyple = self.get_zeyple(DEFAULT_CONFIG_TEMPLATE + '\nforce_encrypt = 1\n')

        zeyple.process_message(contents, ['unknown@zeyple.example.com'])
        self.assert_message_count(0)

        zeyple.process_message(contents, [TEST1_EMAIL])
        self.assert_message_count(1)
        self.assert_message_header(0, 'Subject', 'Verify Email')

    def test_missing_key_notify(self):
        contents = get_test_email()
        zeyple = self.get_zeyple(
            DEFAULT_CONFIG_TEMPLATE + dedent("""\
                [missing_key_rules]
                . = notify
            """)
        )

        sent_messages = zeyple.process_message(contents, ['unknown@zeyple.example.com'])
        self.assert_message_count(1)
        self.assert_message_header(0, 'Subject', 'Missing PGP key')

        sent_messages = zeyple.process_message(contents, [TEST1_EMAIL])
        self.assert_message_count(2)
        self.assert_message_header(1, 'Subject', 'Verify Email')

    def test_missing_key_drop(self):
        contents = get_test_email()
        zeyple = self.get_zeyple(
            DEFAULT_CONFIG_TEMPLATE + dedent("""\
                [missing_key_rules]
                . = drop
            """)
        )

        zeyple.process_message(contents, ['unknown@zeyple.example.com'])
        self.assert_message_count(0)

        zeyple.process_message(contents, [TEST1_EMAIL])
        self.assert_message_count(1)
        self.assert_message_header(0, 'Subject', 'Verify Email')

    def test_missing_key_cleartext(self):
        contents = get_test_email()
        zeyple = self.get_zeyple(
            DEFAULT_CONFIG_TEMPLATE + dedent("""\
                [missing_key_rules]
                . = cleartext
            """)
        )

        zeyple.process_message(contents, ['unknown@zeyple.example.com'])
        self.assert_message_count(1)
        self.assert_message_header(0, 'Subject', 'Verify Email')

        zeyple.process_message(contents, [TEST1_EMAIL])
        self.assert_message_count(2)
        self.assert_message_header(0, 'Subject', 'Verify Email')

    def test_missing_key_complex_config(self):
        contents = get_test_email()
        zeyple = self.get_zeyple(
            DEFAULT_CONFIG_TEMPLATE + dedent("""\
                [missing_key_rules]
                erno\\.testibus\\@example\\.com = cleartext
                frida\\.testibus\\@example\\.com = notify
                .*\\@example\\.com = drop
                . = cleartext
            """)
        )

        zeyple.process_message(contents, ['erno.testibus@example.com'])
        self.assert_message_count(1)
        self.assert_message_header(0, 'Subject', 'Verify Email')

        zeyple.process_message(contents, ['frida.testibus@example.com'])
        self.assert_message_count(2)
        self.assert_message_header(1, 'Subject', 'Missing PGP key')

        zeyple.process_message(contents, ['paul@example.com'])
        self.assert_message_count(2)

        zeyple.process_message(contents, ['unknown@zeyple.example.com'])
        self.assert_message_count(3)
        self.assert_message_header(2, 'Subject', 'Verify Email')

    def test_custom_missing_key_message(self):
        contents = get_test_email()
        missing_key_message_file = os.path.join(self.tmpdir, 'missing_key_message')
        subject = 'No key dude!'
        body = 'xxxYYYzzzäöü'
        write_file(missing_key_message_file, body + '\n')

        zeyple = self.get_zeyple(
            DEFAULT_CONFIG_TEMPLATE + dedent("""\
            missing_key_notification_file = {0}
            missing_key_notification_subject = {1}
            """).format(missing_key_message_file, subject)
        )

        zeyple.process_message(contents, ['unknown@zeyple.example.com'])

        self.assert_message_count(1)
        self.assert_message_header(0, 'To', 'unknown@zeyple.example.com')
        self.assert_message_header(0, 'Subject', subject)
        self.assert_message_header(0, 'Content-Type', 'text/plain; charset="utf-8"')
        assert body in self.get_payload(0)

    def test_groups(self):
        contents = get_test_email()
        write_file(self.homedir + '/gpg.conf', GPG_CONF_CONTENT)
        zeyple = self.get_zeyple()

        zeyple.process_message(contents, [TEST_GROUP])

        self.assert_message_count(1)
        self.assert_envelop_to(0, TEST_GROUP)
        self.assert_message_header(0, 'Subject', 'Verify Email')
