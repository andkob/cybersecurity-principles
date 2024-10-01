package AsymmetricCryptography;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * A client class that simulates secure communication with a server using 
 * asymmetric cryptography. Each client instance generates its own key pair 
 * and can encrypt and decrypt messages.
 */
public class Client {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String algorithm;

    /**
     * Creates a new Client and generates a key pair using the specified algorithm.
     * 
     * @param algorithm The name of the cryptographic algorithm (e.g., "RSA").
     * @throws NoSuchAlgorithmException If the specified algorithm is not supported.
     */
    public Client(String algorithm) throws NoSuchAlgorithmException {
        this.algorithm = algorithm;
        generateKeyPairs();
    }

    /**
     * Generates a key pair for the client using the specified algorithm.
     * 
     * @throws NoSuchAlgorithmException If the cryptographic algorithm is not supported.
     */
    public void generateKeyPairs() throws NoSuchAlgorithmException {
        // Create a key pair
        KeyPair keyPair = CryptoTools.generateKeyPairs("RSA");

        // Save keys (in memory for now)
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    /**
     * Encrypts a message using the recipient's public key and sends the encrypted message.
     * 
     * @param message The plaintext message to be encrypted.
     * @param recipientPublicKey The recipient's {@link PublicKey} for encryption.
     * @return A byte array representing the encrypted message.
     * @throws NoSuchAlgorithmException If the encryption algorithm is not supported.
     * @throws NoSuchPaddingException If the padding scheme is not available.
     * @throws InvalidKeyException If the recipient's public key is invalid.
     * @throws IllegalBlockSizeException If the message size is incompatible with the block size of the cipher.
     * @throws BadPaddingException If the padding of the message is incorrect.
     */
    public byte[] encryptAndSendMessage(String message, PublicKey recipientPublicKey) throws NoSuchAlgorithmException, 
                                                             NoSuchPaddingException,
                                                             InvalidKeyException,
                                                             IllegalBlockSizeException, 
                                                             BadPaddingException {
        return CryptoTools.encryptAndSendMessage(message, recipientPublicKey, algorithm);
    }

    /**
     * Decrypts an encrypted message using the client's private key.
     * 
     * @param encryptedMessageBytes The encrypted message as a byte array.
     * @throws NoSuchAlgorithmException If the decryption algorithm is not supported.
     * @throws NoSuchPaddingException If the padding scheme is not available.
     * @throws InvalidKeyException If the client's private key is invalid.
     * @throws IllegalBlockSizeException If the encrypted message size is incompatible with the block size of the cipher.
     * @throws BadPaddingException If the padding of the encrypted message is incorrect.
     */
    public void decryptAndReadMessage(byte[] encryptedMessageBytes) throws NoSuchAlgorithmException,
                                                                      NoSuchPaddingException,
                                                                      InvalidKeyException,
                                                                      IllegalBlockSizeException,
                                                                      BadPaddingException {
        CryptoTools.decryptAndReadMessage(encryptedMessageBytes, algorithm, privateKey);
    }

    /**
     * Requests the public key from the specified server.
     * 
     * @param target The {@link PseudoServer} from whom to request the public key.
     * @return The {@link PublicKey} of the specified server.
     */
    public PublicKey requestPublicFrom(PseudoServer target) {
        return target.getPublic();
    }

    /**
     * Returns the client's public key.
     * 
     * @return The client's {@link PublicKey}.
     */
    public PublicKey getPublic() {
        return publicKey;
    }
}

