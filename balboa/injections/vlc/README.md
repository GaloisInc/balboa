Run `vlc --gnutls-priorities NORMAL` to launch VLC in graphical mode.

To run VLC without the GUI, use `vlc --gnutls-dir-trust $TRUST_DIR -I dummy --aout dummy https://tcpdump:8443/vorbis.ogg vlc://quit` replacing `$TRUST_DIR` with a directory containing the root CA certificates. Note that, with this second command, no audio will be outputted.

To inject into VLC, follow the instructions in the README in the directory above this, as well as set:

  * `SSLKEYLOGFILE` to a path which either doesn't exist or is a FIFO. IT IS VERY IMPORTANT THAT THERE IS NOT A REGULAR FILE AT THIS PATH
  * `OGG_FILE` to the path of the OGG file that will be streamed in. If set to `NO_REWRITE`, the injection will pass zero bytes to the application.
