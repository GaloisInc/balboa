# SSL woes

The version of `icecast2` that ships with Debian and Ubuntu doesn't come enabled with ssl. This has been [noted](https://github.com/xiph/Icecast-Server/issues/29). The problem, apparently, is that [the OpenSSL license is incompatible with the GPLv2 license of Icecast](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=744815#15), or at least according to Debian developers. Two years ago, someone floated the idea of maybe using another TLS library instead. This hasn't happend.

For now, the makers of Icecast have their [own repos][1].

For Ubuntu bionic (18.04), run :

1. `sudo sh -c "echo deb https://download.opensuse.org/repositories/multimedia:/xiph/xUbuntu_18.04/ ./ >>/etc/apt/sources.list.d/icecast.list"` to add their repo.
2. `wget -qO - https://icecast.org/multimedia-obs.key | sudo apt-key add -` (NOTE: the official docs suggest that you download the key over http, not https. I recommend not doing that.)
3. `sudo apt-get update`
4. `sudo apt-get install icecast2`

# Running Icecast
Run icecast (with the right environment variables set) with `icecast2 -c my-icecast-config.xml`.

You can then use `ezstream` to stream the music into icecast. See the dockerfile and script in `testing/machines/icecast` (though note that, as of this writing, the environment variables are still set for an older version of Balboa; so follow the instructions below to setup the environment variables to inject into icecast, but you can still follow its example in terms of how to run Icecast generally).

# Running the Injection
To inject into Icecast, follow the instructions in the README in the directory above this, as well as set:

  * `OGG_FILE` to the path of the OGG file that will be streamed in.


[1]: https://wiki.xiph.org/Icecast_Server/Installing_latest_version_(official_Xiph_repositories)
