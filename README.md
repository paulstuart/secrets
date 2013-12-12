secrets
=======

Encrypted credentials for accessing multiple servers

It uses an external key and embedded salt string for encryption.

To change the salt string without modifying the code: 

go build/test/install -ldflags "-X secrets.salty my-new-salt-string"
