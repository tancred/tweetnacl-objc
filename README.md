# Objective-C TweetNaCl

Objective-C bindings for the excellent [TweetNaCl](http://tweetnacl.cr.yp.to) cryptographic library.

Because TweetNaCl is a complete implementation of all the public functions of the original [NaCl](http://nacl.cr.yp.to) library,
the bindings should work with that library as well.

This is work in progress and the bindings are not usable yet. Stay tuned for updates.

## Public-key authenticated encryption: CryptoBox

A ```CryptoBox``` is one of the two end-points of a _public-key authenticated encryption_ communications channel. Each end-point holds 1) its secret key and 2) the public key corresponding to the secret key of the other end-point.

```CryptoBoxPublicKey``` is the public part of a keypair. It is derived completely from its corresponding secret key.
```CryptoBoxSecretKey``` is the secret part of a keypair. Must be kept secret.

### An example

Alice wants to send a secret message to Bob.

1. Alice obtains her secret key and Bobs public key.
    ```
    CryptoBoxSecretKey *alicesSecretKey = [CryptoBoxSecretKey keyWithData:sk error:&error];
    CryptoBoxPublicKey *bobsPublicKey = [CryptoBoxPublicKey keyWithData:pk error:&error];
    ```

2. Next, she creates her communications end-point.
    ```
    CryptoBox *box = [CryptoBox boxWithSecretKey:alicesSecretKey publicKey:bobsPublicKey];
    ```

3. Finally, she encrypts the ```message``` with a nonce and sends the ```nonce``` and resulting ```cipher```to Bob, e.g., over a TCP socket.
    ```
    NSData *message = ...;
    CryptoBoxNonce *nonce = [CryptoBoxNonce nonceWithData:n error:&error];
    NSData *cipher = [box encryptMessage:message withNonce:nonce error:&error];
    ```

Bob recieves a message purportedly from Alice.

1. Bob extracts a ```cipher``` and ```nonce``` from the message.
    ```
    NSData *cipher = ...;
    CryptoBoxNonce *nonce = [CryptoBoxNonce nonceWithData:n error:&error];
    ```

2. Bob obtains his secret key and Alice's public key and creates his encryption box.
    ```
    CryptoBoxSecretKey *bobsSecretKey = [CryptoBoxSecretKey keyWithData:sk error:&error];
    CryptoBoxPublicKey *alicesPublicKey = [CryptoBoxPublicKey keyWithData:pk error:&error];
    CryptoBox *box = [CryptoBox boxWithSecretKey:bobsSecretKey publicKey:alicesPublicKey];
    ```

3. He decrypts the message.
    ```
    NSData *message = [box decryptCipher:cipher withNonce:nonce error:&error];
    ```

That's the simple case. In the real world, a proper security protocol has to be established. In the example above, if Eve is able to record the encrypted messages (```cipher``` and ```nonce```) passed between Alice and Bob, and then manages to get hold of Bob's secret key, she will be able to decrypt the whole communication.

The standard way to deal with this is for Alice and Bob to generate temporary keypairs and send each other the public counterparts of these new keys using the encryption boxes described above, i.e., with their "long-term" or "long-lived" keys. When this key exchange has completed, all further communication is done using the new temporary keys. When communication ends the temporary keys are discarded. New keys might need to be negotiated periodically duriong communication.

There are more details that need to be taken care of as well: nonce selection, discarding messages with already seen nonces, timestamps during key exchange, etc, but it all depends on the high-level protcol.
