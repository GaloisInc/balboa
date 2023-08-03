---
title: "Balboa"
...
Balboa is a framework for censorship circumvention. [It was published at USENIX security 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/rosen).

The Balboa source code is _prototype software_. It was written to demonstrate the viability of the Balboa approach.
# Components of Balboa
The Balboa framework is broken up into several different software components
```mermaid
graph TD
    subgraph AppProcess [App Process]
        AppCode[App Code] <-- "SSL_read() and SSL_write()" --> TlsLibrary
        TlsLibrary[TLS Library] <-- "write() and read() calls on sockets" --> TlsRewriter
        TlsLibrary -- "SSLKEYLOGFILE" --> TlsRewriter
        subgraph BalboaInjection[Balboa Injection]
            TlsRewriter[TLS Rewriter] <-- "Plaintext Data" --> Compressor[Pluggable Compressor]
        end
        TlsRewriter <-- "read()/write()" --> libc
    end
    BalboaController[Balboa Controller] -- "Cryptographic Keys" --> TlsRewriter
    BalboaController <-- "Covert Data" --> Compressor
    libc <--> OS
```
## Software Components Dependency Graph
```mermaid
graph TD
    balboa-coroutine --> stallone
    balboa-injection --> balboa-rewriter
    balboa-injection --> mickey-ipc
    balboa-injection --> stallone
    balboa-injections --> balboa-compression-http
    balboa-injections --> balboa-injection
    balboa-injections --> balboa-openssl-injection
    balboa-injections --> balboa-rewriter
    balboa-injections --> conti
    balboa-injections --> stallone
    balboa-openssl-injection --> balboa-injection
    balboa-openssl-injection --> balboa-rewriter
    balboa-rewriter --> balboa-coroutine
    balboa-rewriter --> stallone
    conti --> balboa-coroutine
    conti --> stallone
    balboa-compression-http --> stallone
    balboa-compression-http --> balboa-coroutine
    mickey-ipc --> balboa-coroutine
    mickey-ipc --> stallone
    mickey-server ----> mickey-ipc
    mickey-server --> stallone
```
## Full Crate Dependency Graph
```mermaid
flowchart   LR
 balboa-compression   -->   balboa-coroutine
 balboa-compression   -->   stallone
 balboa-compression-http   -->   balboa-compression
 balboa-compression-http   -->   balboa-coroutine
 balboa-compression-http   -->   balboa-http-header-names
 balboa-compression-http   -->   stallone
 balboa-compression-rtsp   -->   balboa-compression
 balboa-compression-rtsp   -->   balboa-coroutine
 balboa-compression-rtsp   -->   stallone
 balboa-coroutine   -->   stallone
 balboa-covert-signaling-types   -->   stallone
 balboa-injection   -->   balboa-compression
 balboa-injection   -->   balboa-covert-signaling-types
 balboa-injection   -->   balboa-ipc-protocol
 balboa-injection   -->   balboa-rewriter
 balboa-injection   -->   mickey-balboa-ipc
 balboa-injection   -->   stallone
 balboa-injection   -->   stallone-common
 balboa-injection-ffplay-rtsp   -->   balboa-compression
 balboa-injection-ffplay-rtsp   -->   balboa-compression-rtsp
 balboa-injection-ffplay-rtsp   -->   balboa-injection
 balboa-injection-ffplay-rtsp   -->   balboa-openssl-injection
 balboa-injection-ffplay-rtsp   -->   balboa-rewriter
 balboa-injection-firefox   -->   balboa-compression
 balboa-injection-firefox   -->   balboa-compression-http
 balboa-injection-firefox   -->   balboa-injection
 balboa-injection-firefox   -->   balboa-rewriter
 balboa-injection-gnutls-echo   -->   balboa-compression
 balboa-injection-gnutls-echo   -->   balboa-injection
 balboa-injection-gnutls-echo   -->   balboa-rewriter
 balboa-injection-gnutls-echo   -->   balboa-testing-inverting-rewriter
 balboa-injection-icecast   -->   balboa-compression
 balboa-injection-icecast   -->   balboa-injection
 balboa-injection-icecast   -->   balboa-openssl-injection
 balboa-injection-icecast   -->   balboa-rewriter
 balboa-injection-icecast   -->   conti
 balboa-injection-nginx   -->   balboa-compression
 balboa-injection-nginx   -->   balboa-compression-http
 balboa-injection-nginx   -->   balboa-injection
 balboa-injection-nginx   -->   balboa-openssl-injection
 balboa-injection-nginx   -->   balboa-rewriter
 balboa-injection-nginx   -->   stallone
 balboa-injection-openssl-echo   -->   balboa-compression
 balboa-injection-openssl-echo   -->   balboa-injection
 balboa-injection-openssl-echo   -->   balboa-openssl-injection
 balboa-injection-openssl-echo   -->   balboa-rewriter
 balboa-injection-openssl-echo   -->   balboa-testing-inverting-rewriter
 balboa-injection-openssl-echo   -->   stallone
 balboa-injection-socat-rtsp   -->   balboa-compression
 balboa-injection-socat-rtsp   -->   balboa-compression-rtsp
 balboa-injection-socat-rtsp   -->   balboa-injection
 balboa-injection-socat-rtsp   -->   balboa-openssl-injection
 balboa-injection-socat-rtsp   -->   balboa-rewriter
 balboa-injection-vlc   -->   balboa-compression
 balboa-injection-vlc   -->   balboa-injection
 balboa-injection-vlc   -->   balboa-rewriter
 balboa-injection-vlc   -->   conti
 balboa-injection-vlc   -->   stallone
 balboa-ipc-protocol   -->   stallone
 balboa-openssl-injection   -->   balboa-injection
 balboa-openssl-injection   -->   balboa-rewriter
 balboa-recorder-injection   -->   balboa-compression
 balboa-recorder-injection   -->   balboa-injection
 balboa-recorder-injection   -->   balboa-rewriter
 balboa-recorder-injection   -->   stallone
 balboa-rewriter   -->   balboa-compression
 balboa-rewriter   -->   balboa-coroutine
 balboa-rewriter   -->   balboa-covert-signaling-types
 balboa-rewriter   -->   stallone
 balboa-testing-inverting-rewriter   -->   balboa-compression
 conti   -->   balboa-compression
 conti   -->   balboa-conti-crc-sys
 conti   -->   balboa-coroutine
 conti   -->   stallone
 mickey-balboa-ipc   -->   balboa-compression
 mickey-balboa-ipc   -->   balboa-coroutine
 mickey-balboa-ipc   -->   balboa-covert-signaling-types
 mickey-balboa-ipc   -->   balboa-rewriter
 mickey-balboa-ipc   -->   scm-rights
 mickey-balboa-ipc   -->   stallone
 mickey-balboa-ipc   -->   stallone-common
 mickey-protocol   -->   balboa-covert-signaling-types
 mickey-protocol   -->   scm-rights
 mickey-protocol   -->   stallone
 mickey-server   -->   balboa-covert-signaling-types
 mickey-server   -->   mickey-balboa-ipc
 mickey-server   -->   mickey-protocol
 mickey-server   -->   scm-rights
 mickey-server   -->   stallone
 mickey-server   -->   stallone-common
 mickey-server   -->   systemd-ready
 stallone   -->   scm-rights
 stallone   -->   stallone-common
 stallone   -->   stallone-derive
 stallone-common   -->   scm-rights
 stallone-master   -->   stallone-common
 stallone-master   -->   stallone-parsing
 stallone-parsing   -->   stallone
 stallone-parsing   -->   stallone-common
 stallone-tools   -->   stallone-common
 stallone-tools   -->   stallone-master
 stallone-tools   -->   stallone-parsing
 stallone-tools   -->   systemd-ready
 systemd-ready   -->   stallone-common
```