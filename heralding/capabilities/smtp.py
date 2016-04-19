# Copyright (C) 2013 Aniket Panse <contact@aniketpanse.in>
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

# Parts of this code are from secure-smtpd (https://github.com/bcoe/secure-smtpd)

# Aniket Panse <contact@aniketpanse.in> grants Johnny Vestergaard <jkv@unixcluster.dk>
# a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
# copyright license to reproduce, prepare derivative works of, publicly
# display, publicly perform, sublicense, relicense, and distribute [the] Contributions
# and such derivative works.


import asynchat
import asyncore
import base64
import logging
import mailbox
import random
import smtpd
import time
import smtpd
import traceback

from heralding.capabilities.handlerbase import HandlerBase

logger = logging.getLogger(__name__)


class SMTPChannel(smtpd.SMTPChannel):
    def __init__(self, smtp_server, newsocket, fromaddr,
                 smtp_map=None, session=None, opts=None):
        self.options = opts
        # A sad hack because SMTPChannel doesn't
        # allow custom banners, and sends it's own through its
        # __init__() method. When the initflag is False,
        # the push() method is effectively disabled, so the 
        # superclass banner is not sent.
        self._initflag = False
        self.banner = self.options['protocol_specific_data']['banner']

        # States
        self.login_pass_authenticating = False
        self.login_uname_authenticating = False
        self.plain_authenticating = False
        self.cram_authenticating = False

        self.username = None
        self.password = None
        self.digest = None

        self.sent_cram_challenge = None
        self.session = session
        self.options = opts

        smtpd.SMTPChannel.__init__(self, smtp_server, newsocket, fromaddr, decode_data=True)
        asynchat.async_chat.__init__(self, newsocket, map=smtp_map)

        # Now we set the initflag, so that push() will work again.
        # And we push.
        self._initflag = True
        self.push("220 %s" % self.banner)

    def push(self, msg):
        # Only send data after superclass initialization
        if self._initflag:
            smtpd.SMTPChannel.push(self, msg)
            #transmit_msg = msg + '\r\n'
            #asynchat.async_chat.push(self, transmit_msg.encode())

    def close_quit(self):
        self.close_when_done()
        self.handle_close()

    def smtp_QUIT(self, arg):
        self.push('221 Bye')
        self.close_when_done()
        self.close_quit()

    #def collect_incoming_data(self, data):
    #    self.__line.append(data)

    def smtp_EHLO(self, arg):
        if not arg:
            self.push('501 Syntax: HELO/EHLO hostname')
            return
        if self.seen_greeting:
            self.push('503 Duplicate HELO/EHLO')
        else:
            self.push('250-%s Hello %s' % (self.banner, arg))
            self.push('250-AUTH PLAIN LOGIN CRAM-MD5')
            self.push('250 EHLO')

    def smtp_AUTH(self, arg):
        print('AUTH')
        if (self.plain_authenticating and self.login_pass_authenticating and
                self.cram_authenticating):
            self.push('503 Bad sequence of commands')
            self.close_quit()

        if self.cram_authenticating:
            self.cram_authenticating = False
            print('Want to decode: {0}'.format(repr(arg)))
            decoded_bytes = base64.b64decode(arg).decode('ascii')
            print('Now decoded: {0}'.format(repr(decoded_bytes)))
            self.username, self.digest = decoded_bytes.split()
            if self.sent_cram_challenge is None:
                self.push('451 Internal confusion')
                return
            self.session.add_auth_attempt('cram_md5', username=self.username, digest=self.digest,
                                          challenge=self.sent_cram_challenge)
            self.push('535 authentication failed')
            self.close_quit()

        elif self.login_uname_authenticating:
            self.login_uname_authenticating = False
            self.username = base64.b64decode(arg).decode('ascii')
            self.push('334 ' + base64.b64encode(b'Password:').decode('ascii'))
            self.login_pass_authenticating = True
            return

        elif self.login_pass_authenticating:
            self.login_pass_authenticating = False
            self.password = base64.b64decode(arg).decode('ascii')
            self.session.add_auth_attempt('plaintext', username=self.username, password=self.password)

            self.push('535 authentication failed')
            self.close_quit()

        elif self.plain_authenticating:
            self.plain_authenticating = False
            # Our arg will ideally be the username/password
            _, self.username, self.password = base64.b64decode(arg).decode('ascii').split('\x00')
            self.session.add_auth_attempt('plaintext', username=self.username, password=self.password)
            self.push('535 authentication failed')
            self.close_quit()

        elif 'PLAIN' in arg:
            self.plain_authenticating = True
            try:
                _, param = arg.split()
            except ValueError:
                # We need to get the credentials now since client has not sent
                # them. The space after the 334 is important as said in the RFC
                self.push("334 ")
                return
            _, self.username, self.password = base64.b64decode(param).decode('ascii').split('\x00')
            self.session.add_auth_attempt('plaintext', username=self.username, password=self.password)
            self.push('535 authentication failed')
            self.close_quit()

        elif 'LOGIN' in arg:
            param = arg.split()
            if len(param) > 1:
                self.username = base64.b64decode(param[1])
                self.push('334 ' + base64.b64encode(b'Password:').decode('ascii'))
                self.login_pass_authenticating = True
                return
            else:
                self.push('334 ' + base64.b64encode(b'Username:').decode('ascii'))
                self.login_uname_authenticating = True
                return

        elif 'CRAM-MD5' in arg:
            self.cram_authenticating = True
            r = random.randint(5000, 20000)
            t = int(time.time())

            # challenge is of the form '<24609.1047914046@awesome.host.com>'
            self.sent_cram_challenge = "<" + str(r) + "." + str(t) + "@" + self.__fqdn + ">"
            self.push("334 " + base64.b64encode(self.sent_cram_challenge.encode()).decode())
            return

    # This code is taken directly from the underlying smtpd.SMTPChannel
    # support for AUTH is added.
    def found_terminator(self):
        print('blah')
        line = self._emptystring.join(self.received_lines)
        print('blah2')
        print('Data:', repr(line), file=smtpd.DEBUGSTREAM)
        self.received_lines = []
        if self.smtp_state == self.COMMAND:
            sz, self.num_bytes = self.num_bytes, 0
            if not line:
                self.push('500 Error: bad syntax')
                return
            if not self._decode_data:
                line = str(line, 'utf-8')
            i = line.find(' ')

            if (self.login_uname_authenticating or
                    self.login_pass_authenticating or
                    self.plain_authenticating or
                    self.cram_authenticating):
                # If we are in an authenticating state, call the
                # method smtp_AUTH.
                arg = line.strip()
                command = 'AUTH'
            elif i < 0:
                command = line.upper()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i + 1:].strip()
            max_sz = (self.command_size_limits[command]
                      if self.extended_smtp else self.command_size_limit)
            if sz > max_sz:
                self.push('500 Error: line too long')
                return
            method = getattr(self, 'smtp_' + command, None)
            if not method:
                self.push('500 Error: command "%s" not recognized' % command)
                return
            method(arg)
            return
        else:
            if self.smtp_state != self.DATA:
                self.push('451 Internal confusion')
                self.num_bytes = 0
                return
            if self.data_size_limit and self.num_bytes > self.data_size_limit:
                self.push('552 Error: Too much mail data')
                self.num_bytes = 0
                return
            # Remove extraneous carriage returns and de-transparency according
            # to RFC 5321, Section 4.5.2.
            data = []
            for text in line.split(self._linesep):
                if text and text[0] == self._dotsep:
                    data.append(text[1:])
                else:
                    data.append(text)
            self.received_data = self._newline.join(data)
            args = (self.peer, self.mailfrom, self.rcpttos, self.received_data)
            kwargs = {}
            if not self._decode_data:
                kwargs = {
                    'mail_options': self.mail_options,
                    'rcpt_options': self.rcpt_options,
                }
            status = self.smtp_server.process_message(*args, **kwargs)
            self._set_post_data_state()
            if not status:
                self.push('250 OK')
            else:
                self.push(status)


class DummySMTPServer(object):
    def __init__(self):
        self.mboxpath = None

    def process_message(self, peer, mailfrom, rcpttos, data):
        logging.info('Got new mail, peer ({}), from ({}), to ({})'.format(peer, mailfrom, rcpttos))
        if self.mboxpath is not None:
            mbox = mailbox.mbox(self.mboxpath, create=True)
            mbox.add(data)


class smtp(HandlerBase):
    def __init__(self, options):
        super(smtp, self).__init__(options)
        self._options = options

    def execute_capability(self, address, socket, session):
        local_map = {}
        server = DummySMTPServer()
        SMTPChannel(server, socket, address, session=session,
                    smtp_map=local_map, opts=self._options)
        asyncore.loop(map=local_map)
