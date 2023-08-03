---
title: "Mickey"
...

# Use-Case

The balboa injection, itself, provides a pull-based interface to receive covert data and a push-based interface to send covert data. The Balboa code injected process (e.g. web browser or web server process) will give the next level in the stack covert bytes that it has received. When it has room for new covert bytes, it will ask the next level in the stack for a given number of covert bytes.

Balboa guarantees that, for each side of the full-duplex connection, the receiver will receive a prefix of the data that was sent, even in the presence of an active, malicious adversary.

The in-process Balboa code calls the Balboa controller on the hot path to push covert data into it and pull covert data out of it. Because this occurs on the hot path, any latency in the Balboa controller here gets exposed a network observer/adversary. If the Balboa controller takes too long to run, this could cause Balboa to be detected.

What's more, in order for Balboa to be useful, we want to hook it up to real-world applications (clients), ideally through a TCP-like (reliable, in-order) interface. When covert data comes in from Balboa, if the client isn't ready to receive more data yet, we need to do something with the data that we've just received. We could put the incoming data into a buffer, but we don't want this buffer to grow without bound! So we need to figure out what to do if the buffer is completely full.

We'd also like to be able to spread a single stream of covert data across several channels. Since Balboa covert channels can drop data from the end of the stream (it only guarantees that a prefix of data is available), we also need to contend with data loss.

To solve these problems, we wrote Mickey. Mickey fulfills the role of the Balboa controller to feed it and receive covert data. Rather than feeding it the raw covert data from the client, Mickey runs a custom wire protocol over Balboa. This wire protocol breaks covert data into chunks which can be acknowledged and re-sent. If there's no room for a chunk in the incoming window, that chunk will be dropped and won't be acknowledged, which will cause the instance of mickey on the sender to try re-sending the missed chunk.

This solution solves are data loss problem, since Mickey uses acknowledgments to track which chunks have been received. In addition, chunks can be sent over multiple different Balboa streams, meaning that more Balboa streams can enable better throughput.

Because Mickey needs to be able to send/receive acknowledgments, it only works over bidirectional channels.

## Are we re-inventing TCP?

No.

Protocols like TCP or QUIC which need carefully tuned algorithms in order to estimate network bandwidth and determine how much data to send and when. In our setting, we don't need to make any of these decisions--Balboa will tell us exactly when it can send data, and how many bytes it can send. Unlike IP, which asks for TCP to push data into it, Balboa uses a pull interface to receive data, so we don't have this problem. Consequently, trying to run a protocol like TCP or QUIC over the transport that Balboa exposes would be inefficient, as TCP/QUIC would need to predict when Balboa is asking for data--but there's not need to try to predict that. Balboa will just ask when it wants data!

# Interface
TODO: do we want to explain the capability stuff here? Do we want to keep it in a separate branch?