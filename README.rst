This is a simple command-line tool to encrypt and decrypt files using AES-GCM.
The key size is currently hardcoded to 128 bits.
The tool uses the OpenSSL EVP API and is based on the encrypt() and decrypt()
functions found at `Stack Overflow`_ and the `OpenSSL Wiki`_.

* To build, type ``make``
* ``./aesgcm -h`` shows the usage text
* ``make test`` runs a self-test (``make test V=1`` is more verbose)

.. _Stack Overflow: https://stackoverflow.com/questions/9889492
.. _OpenSSL Wiki: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
