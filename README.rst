======================
 Weechat alert client
======================

This is a simple Python-based client for weechat, for the purpose of
tracking highlights and direct messages.  This can be used as a simple
aggregated buffer of such, or as input to another tool, such as an
alert tool.

This is not thoroughly tested and the code could frnakly be better; I
merely use this for my work and it works well enough for me.  I'm
simply making this available in case others might get use from it.
Patches are welcome though.

To use, assuming HTTPS without server cert verification::

  "python3 -m weechat_alert_client <host> <port> -s"

Or, with server cert verification::

  "python3 -m weechat_alert_client <host> <port> -s -c <cacert>"

The tool will prompt for necessary setup of a password file.  You
*are* using a password for your bouncer, right?

Cheers!

- Paul Goins
