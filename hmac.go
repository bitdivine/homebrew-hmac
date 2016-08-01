package main

func HMAC(key []byte, message[]byte) (hmac [32]byte) {
	hash := TEST_SHA256
	key_hash := hash(key)					// Make the key fixed length.
	msg_hash := hash( append( key_hash[:], message... ) )	// Keyed hash of the message.
	return hash(append(key_hash[:], msg_hash[:]...))	// Final application of the key to prevent length extension attacks.
}
