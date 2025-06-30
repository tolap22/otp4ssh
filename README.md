otp4ssh
=======

Add OTP (one-time password) authentication to your SSH server.

    user@localhost:~$ ssh server
    Enter passphrase for key '/home/user/.ssh/id_rsa': 
    One-time password: 123456
    Incorrect code. Please try again.

    One-time password: 653794
    user@server:~$ 


The following instructions are based on ubuntu, but they can be adapted for other Linux distributions.
Depending on linux distribution Python 2 or Python 3 may be installed, otp4ssh supports both.

Installation
------------

Copy `ssh-otp` and `ssh-otp.py` to `/usr/local/bin`:

    sudo mkdir -p /usr/local/bin
    sudo cp ssh-otp ssh-otp.py

Add the following line in your `/etc/ssh/sshd_config`:

    ForceCommand /usr/local/bin/ssh-otp login

And restart sshd:

    sudo restart ssh


Enable
------

If no one-time password has been generated the ssh-otp skips asking
for OTP.
If you generate a one-time password secret for current user with:

    ssh-otp setup

You will need to set up your authenticator using the QR code link
and type in the displayed code on your authenticator to actually enable
one-time password authentication on SSH conneciton.


The generated configuration file will be available at:

    ~/.ssh/otp


Disable
-------

To disable otp for the current user:

    ssh-otp reset


Non-interactive commands
------------------------

To use commands like `scp`, you need to pass in the one-time password
through a `OTP` environment variable.

In `/etc/ssh/sshd_config`, add `OTP` to the list of `AcceptEnv`:

    AcceptEnv OTP

On the client machine, instruct ssh to send the `OTP` environment by adding
the following in your `~/.ssh/config`:

    Host *
    SendEnv OTP

Now set the `OTP` environment before sending the command over ssh:

    OTP="123456" scp server:~/.ssh/authorized_key .

