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

gQUIC versions are deprecated and disabled by default.  There remains no
technical reason why a single engine instance could not be used both for
client and server connections.  It is just work.  For example, the single
engine settings :type:`lsquic_engine_settings` will have to be separated
into client and server settings, as the two usually do need to have
separate settings.
