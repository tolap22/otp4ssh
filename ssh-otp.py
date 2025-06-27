#!/usr/bin/env python

from __future__ import with_statement, print_function
import sys
import os
import re
import json
import argparse
import signal
import hmac
import hashlib
import struct
import base64
import time
import socket

# Use Python 3's built-in compatibility
try:
    # Python 3
    from urllib.parse import quote, urlencode
    input_func = input
    oct_mode = 0o600
except ImportError:
    # Python 2
    from urllib import quote, urlencode
    input_func = raw_input
    oct_mode = 0o600  # Use 0o prefix for Python 3 compatibility

class Action(object):
    """
    Action base.
    """

    def __init__(self):
        """
        Loads configuration from ~/.ssh/otp
        """

        self.config = {
            'debug': False,
            'enable': False,
            'secret': '',
            'timeout': 120,
            'delay': 3,
            'drift_backward': 1,
            'drift_forward': 1,
        }
        self.config_path = os.path.join(os.environ['HOME'], '.ssh', 'otp')
        self.load()
    
    def yaml_load(self, stream):
        """Minimal YAML loader that handles basic key-value pairs"""
        try:
            content = stream.read()
            # Handle bytes to string conversion
            if hasattr(content, 'decode'):
                content = content.decode('utf-8')
            if not content.strip():
                return {}
            
            # Simple YAML to JSON conversion for basic key-value pairs
            result = {}
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Match key: value pattern
                match = re.match(r'^(\w+):\s*(.+)$', line)
                if match:
                    key = match.group(1)
                    value_str = match.group(2).strip()
                    
                    # Convert value types
                    if value_str.lower() in ('true', 'false'):
                        value = value_str.lower() == 'true'
                    elif value_str.isdigit():
                        value = int(value_str)
                    elif value_str.startswith('"') and value_str.endswith('"'):
                        value = value_str[1:-1]
                    else:
                        value = value_str
                    
                    result[key] = value
            
            return result
        except Exception as e:
            # Return empty dict on any error (including file not found)
            return {}

    def yaml_dump(self, data, stream=None, default_flow_style=False):
        """Minimal YAML dumper"""
        lines = []
        for key, value in data.items():
            if isinstance(value, bool):
                value_str = str(value).lower()
            elif isinstance(value, str):
                value_str = '"{}"'.format(value)
            else:
                value_str = str(value)
            lines.append('{}: {}'.format(key, value_str))
        
        text = '\n'.join(lines)
        if stream is None:
            return text
        # Handle string to bytes conversion
        if hasattr(stream, 'write'):
            if hasattr(text, 'encode'):
                stream.write(text.encode('utf-8'))
            else:
                stream.write(text)

    def load(self):
        try:
            with open(self.config_path, 'rb') as f:
                self.config.update(self.yaml_load(f) or {})
        except (IOError, OSError):
            pass

    def save(self):
        with open(self.config_path, 'wb') as f:
            self.yaml_dump(self.config, f, default_flow_style=False)
        os.chmod(self.config_path, oct_mode)

    def check(self, code):
        drift_backward = max(0, self.config['drift_backward'])
        drift_forward = max(0, self.config['drift_forward'])

        for drift in range(-drift_backward, drift_forward + 1):
            if code == self.totp(self.config['secret'], drift=drift):
                return True
        return False

    def totp(self, key, length=6, hash=hashlib.sha1, period=30, drift=0):
        counter = int(int(time.time()) / period) + drift
        return self.hotp(key, counter, length=length, hash=hash, drift=0)

    def hotp(self, key, counter, length=6, hash=hashlib.sha1, drift=0):
        counter = struct.pack('>Q', counter + drift)
        key = base64.b32decode(key)

        digest = hmac.new(key, counter, hash).digest()

        # Handle bytes indexing for Python 2/3 compatibility
        try:
            # Python 3: digest[-1] returns int directly
            offset = digest[-1] & 0xF
        except TypeError:
            # Python 2: digest[-1] returns string, need ord()
            offset = ord(digest[-1]) & 0xF
            
        value = struct.unpack('>L', digest[offset:offset + 4])[0] & 0x7FFFFFFF
        code = ('%010d' % value)[-length:]
        return code

class Login(Action):

    def __init__(self):
        super(Login, self).__init__()

        # dump environ for debugging
        if self.config['debug']:
            for name, value in os.environ.items():
              sys.stderr.write('%s = %s\n' % (name, value))

        # setup timeout
        signal.signal(signal.SIGALRM, self.fail)

    def shell(self, command=''):
        if command:
            os.execl('/bin/bash', '/bin/bash', '-c', command)
        else:
            shell = os.environ['SHELL']
            os.execl(shell, shell, '-l')
        assert False

    def success(self):
        self.shell(os.environ.get('SSH_ORIGINAL_COMMAND', ''))

    def fail(self, *args, **kwargs):
        os._exit(1)

    def run(self):
        # if not enabled, then simply run shell
        if not self.config['enable']:
            self.success()

        # is the code set in environment?
        code = os.environ.get('OTP', '')
        if code:
            if self.check(code):
                self.success()
            else:
                self.fail()

        # setup timeout
        signal.alarm(self.config['timeout'])

        # let user try until success or timeout
        try:
            while True:
                # get code
                sys.stderr.write('One-time password: ')
                sys.stderr.flush()

                code = input_func().strip()
                if self.check(code):
                    break

                # delay
                time.sleep(self.config['delay'])
                sys.stderr.write('Incorrect code. Please try again.\n\n')

        except (KeyboardInterrupt, EOFError):
            self.fail()

        # disable timeout
        signal.alarm(0)

        self.success()

class Setup(Action):

    def run(self):
        sys.stdout.write('\n')

        if not self.config['secret']:
            self.generate()
           
            sys.stdout.write('New one-time password secret\n')
            sys.stdout.write('----------------------------\n')
        else:
            sys.stdout.write('Existing one-time password secret\n')
            sys.stdout.write('---------------------------------\n')

        self.display()

        if self.config['enable']:
            return
        
        self.test()

    def generate(self):
        # 320 bit of entropy
        secret = os.urandom(40)
        secret = base64.b32encode(secret)
        # Handle bytes to string conversion
        if hasattr(secret, 'decode'):
            secret = secret.decode('ascii')
        self.config['secret'] = secret
        self.save()

    def display(self):
        sys.stdout.write('Secret: %s\n' % self.config['secret'])

        otpauth_url = 'otpauth://totp'
        otpauth_url += quote('/ssh %s@%s' % (os.environ['USER'], socket.gethostname()))
        otpauth_url += '?' + urlencode({
            'secret': self.config['secret']
        })

        # Use QR Server API (working alternative to Google Charts)
        qrcode_url = 'https://api.qrserver.com/v1/create-qr-code/?' + urlencode({
            'size': '512x512',
            'data': otpauth_url,
            'format': 'png'
        })
        
        sys.stdout.write('QRCode: %s\n' % qrcode_url)
        sys.stdout.write('otpauth URL: %s\n' % otpauth_url)
        sys.stdout.write('Status: %s\n' % ('Enabled' if self.config['enable'] else 'Disabled'))
        sys.stdout.write('\n')
        sys.stdout.write('Setup Instructions:\n')
        sys.stdout.write('1. Open the QRCode URL in your browser to see the QR code\n')
        sys.stdout.write('2. Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)\n')
        sys.stdout.write('3. Or manually enter the secret: %s\n' % self.config['secret'])
        sys.stdout.write('4. Test the setup by entering a code when prompted\n')
        sys.stdout.write('\n')

    def test(self):
        sys.stdout.write('To enable one-time password, please setup your authenticator.\n')

        try:
            while True:
                # get code
                sys.stderr.write('One-time password: ')
                sys.stderr.flush()

                code = input_func().strip()
                if self.check(code):
                    break

                sys.stderr.write('Incorrect code. Please try again.\n\n')

        except (KeyboardInterrupt, EOFError):
            sys.stdout.write('\nFailed to enable one-time password.\n')
            sys.stdout.write('Please rerun setup to try again.\n')
            sys.exit(1)

        self.config['enable'] = True
        self.save()

        sys.stdout.write('Successful! One-time password is now enabled.\n')
        sys.exit(0)

class Reset(Action):
    def run(self):
        self.config['secret'] = ''
        self.config['enable'] = False
        self.save()

ACTIONS = {
    'login': Login,
    'setup': Setup,
    'reset': Reset,
}

def parse_args():
    parser = argparse.ArgumentParser(description='SSH One-time Password Authentication')
    parser.add_argument('action', choices=ACTIONS.keys())
    return parser.parse_args()

def main(args):
    action_cls = ACTIONS[args.action]
    action = action_cls()
    action.run()

if __name__ == '__main__':
    main(parse_args()) 