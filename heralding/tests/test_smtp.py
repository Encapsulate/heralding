# Copyright (C) 2012 Aniket Panse <contact@aniketpanse.in
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Aniket Panse <contact@aniketpanse.in> grants Johnny Vestergaard <jkv@unixcluster.dk>
# a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
# copyright license to reproduce, prepare derivative works of, publicly
# display, publicly perform, sublicense, relicense, and distribute [the] Contributions
# and such derivative works.


import base64
import hmac
import smtplib

import gevent.monkey
from gevent.server import StreamServer

from heralding.capabilities import smtp
from heralding.reporting.reporting_relay import ReportingRelay

gevent.monkey.patch_all()

import unittest


class SmtpTests(unittest.TestCase):
    def setUp(self):
        self.reportingRelay = ReportingRelay()
        self.reportingRelay.start()

    def tearDown(self):
        self.reportingRelay.stop()

    def test_connection(self):
        """ Tries to connect and run a EHLO command. Very basic test.
        """

        # Use uncommon port so that we can run test even if the Honeypot is running.
        options = {'enabled': 'True', 'port': 0, 'protocol_specific_data': {'banner': 'test'},
                   'users': {'test': 'test'},}
        cap = smtp.smtp(options)
        srv = StreamServer(('0.0.0.0', 0), cap.handle_session)
        srv.start()

        smtp_ = smtplib.SMTP('127.0.0.1', srv.server_port, local_hostname='localhost', timeout=15)
        smtp_.ehlo()
        smtp_.quit()
        srv.stop()

    def test_AUTH_CRAM_MD5_reject(self):
        """ Makes sure the server rejects all invalid login attempts that use the
            CRAM-MD5 Authentication method.
        """

        options = {'enabled': 'True', 'port': 0, 'protocol_specific_data': {'banner': 'Test'},
                   'users': {'someguy': 'test'}}
        cap = smtp.smtp(options)
        srv = StreamServer(('0.0.0.0', 0), cap.handle_session)
        srv.start()

        def encode_cram_md5(challenge, user, password):
            challenge = base64.decodebytes(challenge)
            response = user + ' ' + hmac.HMAC(password.encode('ascii'), challenge).hexdigest()
            encoded_string = response.encode('ascii')
            return base64.b64encode(encoded_string)

        smtp_ = smtplib.SMTP('127.0.0.1', srv.server_port, local_hostname='localhost', timeout=15)
        _, resp = smtp_.docmd('AUTH', 'CRAM-MD5')
        cram_md5 = encode_cram_md5(resp, 'test', 'test').decode('ascii')

        code, resp = smtp_.docmd(cram_md5)
        # For now, the server's going to return a 535 code.
        self.assertEqual(code, 535)
        srv.stop()

    def test_AUTH_PLAIN_reject(self):
        """ Makes sure the server rejects all invalid login attempts that use the PLAIN Authentication method.
        """
        options = {'enabled': 'True', 'port': 0, 'protocol_specific_data': {'banner': 'Test'},
                   'users': {'someguy': 'test'}}

        cap = smtp.smtp(options)
        srv = StreamServer(('0.0.0.0', 0), cap.handle_session)
        srv.start()

        smtp_ = smtplib.SMTP('127.0.0.1', srv.server_port, local_hostname='localhost', timeout=15)
        arg = '\0%s\0%s' % ('test', 'test')
        code, resp = smtp_.docmd('AUTH', 'PLAIN ' + base64.b64encode(arg.encode()).decode('ascii'))
        self.assertEqual(code, 535)
        srv.stop()

    def test_AUTH_LOGIN_reject(self):
        """ Makes sure the server rejects all invalid login attempts that use the LOGIN Authentication method.
        """

        options = {'enabled': 'True', 'port': 0, 'protocol_specific_data': {'banner': 'Test'},
                   'users': {'someguy': 'test'}}

        cap = smtp.smtp(options)
        srv = StreamServer(('0.0.0.0', 0), cap.handle_session)
        srv.start()

        smtp_ = smtplib.SMTP('127.0.0.1', srv.server_port, local_hostname='localhost', timeout=15)
        smtp_.docmd('AUTH', 'LOGIN')
        smtp_.docmd(base64.b64encode(b'test').decode('ascii'))
        code, resp = smtp_.docmd(base64.b64encode(b'test').decode('ascii'))
        self.assertEqual(code, 535)
        srv.stop()


if __name__ == '__main__':
    unittest.main()
