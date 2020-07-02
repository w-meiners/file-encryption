Simple file encryption using pynacl

Alice wants to transfer the file Rätsel.png to Bob. 

Here is, what she needs to do.

1. Alice creates a secret and a public key and transfers her public key to Bob

2. Bob creates a secret and a public key and transfers his public to Alice

3. Alice copies Bobs public key to his keys-folder (./.encr) and encrypts the file Rätsel.png to Rätsel.png.encr

4. Alice transports the result to Bob

5. Bob copies Alices public key to his keys-folder (./.encr) and decrypts the file Rätsel.png.encr to Rätsel.png

6. Bob views the content of the file Rätsel.png
