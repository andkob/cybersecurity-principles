package AsymmetricCryptography;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Utility class for cryptographic operations, including key pair generation, 
 * encryption, and decryption of messages.
 */
public class CryptoTools {

    /**
     * Generates a key pair for encryption and decryption using the specified algorithm.
     * 
     * @param algorithm The name of the algorithm to be used for key pair generation (e.g., "RSA").
     * @return The generated {@link KeyPair} containing a public and private key.
     * @throws NoSuchAlgorithmException If the specified algorithm is not supported.
     */
    public static KeyPair generateKeyPairs(String algorithm) throws NoSuchAlgorithmException {
        // Create a key pair
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(2040);
        KeyPair keyPair = generator.generateKeyPair();

        return keyPair;
    }

    /**
     * Encrypts a message using the recipient's public key and the specified algorithm,
     * and prints the Base64-encoded encrypted message.
     * 
     * @param message The plaintext message to be encrypted.
     * @param recipientPublicKey The recipient's {@link PublicKey} for encryption.
     * @param algorithm The algorithm to be used for encryption (e.g., "RSA").
     * @return A byte array representing the encrypted message.
     * @throws NoSuchAlgorithmException If the encryption algorithm is not supported.
     * @throws NoSuchPaddingException If the padding scheme is not available.
     * @throws InvalidKeyException If the provided public key is invalid.
     * @throws IllegalBlockSizeException If the message size is incompatible with the block size of the cipher.
     * @throws BadPaddingException If the padding of the message is incorrect.
     */
    public static byte[] encryptAndSendMessage(String message, PublicKey recipientPublicKey, String algorithm) throws NoSuchAlgorithmException, 
                                                                                             NoSuchPaddingException,
                                                                                             InvalidKeyException,
                                                                                             IllegalBlockSizeException, 
                                                                                             BadPaddingException {
        // Initialize a cipher for encryption with the public key
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);

        // Perform the encryption operation on data
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = cipher.doFinal(messageBytes);

        System.out.println("Sending encrypted message:\n" + Base64.getEncoder().encodeToString(encryptedMessageBytes));

        return encryptedMessageBytes;
    }

    /**
     * Decrypts an encrypted message using the specified algorithm and the recipient's private key,
     * and prints the decrypted message.
     * 
     * @param encryptedMessageBytes The encrypted message as a byte array.
     * @param algorithm The algorithm to be used for decryption (e.g., "RSA").
     * @param privateKey The recipient's {@link PrivateKey} for decryption.
     * @throws NoSuchAlgorithmException If the decryption algorithm is not supported.
     * @throws NoSuchPaddingException If the padding scheme is not available.
     * @throws InvalidKeyException If the provided private key is invalid.
     * @throws IllegalBlockSizeException If the encrypted message size is incompatible with the block size of the cipher.
     * @throws BadPaddingException If the padding of the encrypted message is incorrect.
     */
    public static void decryptAndReadMessage(byte[] encryptedMessageBytes, String algorithm, PrivateKey privateKey) throws NoSuchAlgorithmException,
                                                                                                                           NoSuchPaddingException,
                                                                                                                           InvalidKeyException,
                                                                                                                           IllegalBlockSizeException,
                                                                                                                           BadPaddingException {
        System.out.println("Encrypted message received.");                                                                
        // Initialize a cipher for encryption with the public key
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey); // decrypt with own private key

        // Perform the decryption operation on data
        byte[] decryptedMessageBytes = cipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        System.err.println("Decrypted message is: " + decryptedMessage);
    }
}
