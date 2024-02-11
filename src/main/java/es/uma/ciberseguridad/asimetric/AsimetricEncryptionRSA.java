package es.uma.ciberseguridad.asimetric;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

/**
 * This class shows how to use RSA to sign and verify a text.
 * The text is signed using the SHA-256 algorithm.
 * The signature is saved in a file named B.bin.
 *
 * @author Andrés Samuel Podadera González
 * @version 1.0
 * @since 1.0
 */
public class AsimetricEncryptionRSA {
    public static void main(String[] args) {
        
        byte[] textSigned = null;
        try {
            // Generate RSA key pair
            KeyPair keys = generateKeyPair();
            PublicKey publicKey = keys.getPublic();
            PrivateKey privateKey = keys.getPrivate();

            // Text to sign
            String text = "Andrés Samuel Podadera González";

            // To sign the text
            textSigned = signText(text, privateKey);

            // Save the signature in a file named B.bin
            saveSignature(textSigned);

            // Verify the signature from a file
            verifySignatureFromFile(text, "src/main/java/es/uma/ciberseguridad/asimetric/B.bin", publicKey);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Save the signature in a file named B.bin
        try (FileOutputStream fos = new FileOutputStream("src/main/java/es/uma/ciberseguridad/asimetric/B.bin")) {
            if (textSigned != null)
                fos.write(textSigned);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    /**
     * This method generates a RSA key pair.
     *
     * @return a KeyPair object with the public and private key
     * @throws NoSuchAlgorithmException if the algorithm is not available
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Length of the RSA key
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Return a KeyPair object with the public and private key
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * This method signs a text using a private key.
     *
     * @param text       the text to sign
     * @param privateKey the private key
     * @return a byte array with the signed text
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidKeyException      if the key is invalid
     * @throws SignatureException       if the signature is invalid
     */
    public static byte[] signText(String text, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(text.getBytes());

        // Return the signed text
        return signature.sign();
    }

    /**
     * This method saves the signature in a file named B.bin.
     *
     * @param textSigned the signature to save
     */
    public static void saveSignature(byte[] textSigned) {
        // Save the signature in a file named B.bin
        try (FileOutputStream fos = new FileOutputStream("src/main/java/es/uma/ciberseguridad/asimetric/B.bin")) {
            fos.write(textSigned);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    /**
     * This method verifies the signature from a file.
     *
     * @param text      the text to verify
     * @param path      the path of the file with the signature
     * @param publicKey the public key
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidKeyException      if the key is invalid
     * @throws SignatureException       if the signature is invalid
     * @throws IOException              if an I/O error occurs
     */
    public static void verifySignatureFromFile(String text, String path, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        // Read the signature from the file
        byte[] textSignedFromFile = null;
        try {
            textSignedFromFile = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path));
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }

        // Initialize the signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(text.getBytes());

        // Verify the signature
        boolean isCorrect = signature.verify(textSignedFromFile);
        System.out.println("Is the signature correct? " + (isCorrect ? "Yes" : "No"));
    }
}
    



