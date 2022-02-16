# lookupippoc
A proof of concept to test using AddrinfoEx with events

The net package for Go is using Addrinfo to do address resolution. This
is a synchronous call which results in ctx context not being able to cancel
a request as well as each concurrent call ties up a O/S level thread. This
repository is a proof of concept to see if AddrinfoEx is a reasonable alternative
to Addrinfo. Note that AddrinfoEx is only available in later versions of
Windows so the code has to check to make sure that AddrinfoEx is available
(as well as WaitForMultipleObjects). Other possible drawbacks include the
additional complexity. AddrinfoEx does not support IO Completion Ports, only
IO Completion Routines and Events. I don't see any way to support IO Completion
Routines without a hack to the Go runtime so this POC will use Events.

The existing Addrinfo implementation limits the number of concurrent Addrinfo
calls to 500 with no comment as to why this limit. This POC will use a limit
of 512 (8 * 64) just to be similar to the original code but this approach should
not be used in production without some research as to why the 500 limit exists
and should it be any different when using AddrinfoEx. 