package AsymmetricCryptography;

import java.security.PublicKey;

/**
 * A demonstration class that simulates secure communication between a client and a server
 * using asymmetric cryptography. The client encrypts a message with the server's public key, 
 * and the server decrypts the message with its private key.
 * 
 * This program demonstrates the interaction between a {@link PseudoServer} and a {@link Client}.
 * The client encrypts a message using the server's public key, and the server decrypts it using 
 * its private key.
 */
public class Demo {
    
    public static void main(String[] args) {
        try {
            // server is initialized with its own key pair
            PseudoServer server = new PseudoServer("RSA");

            // client is initialized with its own key pair
            Client client = new Client("RSA");

            System.out.println("\n- Client -");
            // client requests the public key from the server
            PublicKey serverPublic = client.requestPublicFrom(server);
            // client uses this key to encrypt its message for only the server to decrypt
            byte[] encryptedMessage = client.encryptAndSendMessage("goodbye world", serverPublic);

            System.out.println("\n- Server -");
            // server decrypts the encrypted message with its own private key
            server.decryptAndReadMessage(encryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
