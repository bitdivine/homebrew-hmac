compute-hmac
============

A toy HMAC implementation.


# Usage:

    # Build the program:
    make
    # Use it:
    ./compute-hmac secretkey somemessage
    # Or, better, in a way that doesn't leave your key in your shell history:
    < xargs ./compute-hmac
    secretkey somemessage
    <ctl-D>

