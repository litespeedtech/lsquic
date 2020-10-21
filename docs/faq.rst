**************************
Frequently Asked Questions
**************************

API/Design
==========

*Why have a separate engine for server and client?  Surely traffic
could be differentiated as much as it needs to be internally in one
engine?*

The traffic *cannot* be differentiated for gQUIC versions Q046 and Q050.
This is because in these versions, the server never includes a connection
ID into the packets it sends to the client.  To have more than one
connection, then, the client must open a socket per connection: otherwise,
the engine would not be able to dispatch incoming packets to correct
connections.

To aid development, there is a :macro:`LSQUIC_FORCED_TCID0_VERSIONS` that
specifies the list of versions with 0-sized connections.  (If you, for
example, want to turn them off.)

Once gQUIC becomes deprecated in the future, there will remain no technical
reason why a single engine instance could not be used both for client and
server connections.  It will be just work.  For example, the single
engine settings :type:`lsquic_engine_settings` will have to be separated
into client and server settings, as the two usually do need to have
separate settings.

Example Programs
================

*http_client does not work with www.google.com, www.facebook.com, etc.*

Check the version.  By defaut, ``http_client`` will use the latest supported
version (at the time of this writing, "h3-31"), while the server may be using
an older version, such as "h3-29".  Adding ``-o version=h3-29`` to the
command line may well solve your issue.

There is an `outstanding bug`_ where lsquic client does not perform version
negotiation correctly for HTTP/3.  We do not expect this to be fixed, because
a) this version negotiation mechanism is likely to become defunct when QUIC v1
is released and b) version negotiation is not necessary for an HTTP/3 client,
because the other side's version is communicated to it via the ``Alt-Svc`` HTTP
header.

.. _`outstanding bug`: https://github.com/litespeedtech/lsquic/issues/180
