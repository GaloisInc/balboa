UNIX_SOCKET_MAX_PATH_LEN = 108
"""
For various technical reasons, there's a rather short limit on the maximum path length of a UNIX
socket. To avoid hard-to-diagnose errors, we try to manually check UNIX socket paths against this
length.
"""
