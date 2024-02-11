package es.uma.ciberseguridad.asimetric;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class shows how to use HMAC to sign and verify a text.
 * The HMAC is calculated using the SHA-256 algorithm.
 * The HMAC is saved in a file named C.bin.
 *
 * @author Andrés Samuel Podadera González
 */
public class AsimetricEncryptionHMAC {
    public static void main(String[] args) throws Exception {
        
        // Generate a secret key for HMAC
        SecretKey secretKey = generateSecretKey();

        // Text to sign with HMAC
        String texto = "Andrés Samuel Podadera González";

        // Calculate the HMAC
        byte[] hmac = calculateHMAC(texto.getBytes(), secretKey);

        // Save the HMAC in a file named C.bin
        try (FileOutputStream fos = new FileOutputStream("src/main/java/es/uma/ciberseguridad/asimetric/C.bin")) {
            fos.write(hmac);
        }

        // Verify the HMAC from a file
        verifyHMACFromFile(texto, "src/main/java/es/uma/ciberseguridad/asimetric/C.bin", secretKey);
    }

    /**
     * Generate a secret key for HMAC
     *
     * @return SecretKey object
     * @throws NoSuchAlgorithmException If the algorithm is not available
     */
    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        return keyGen.generateKey();
    }

    /**
     * Calculate the HMAC
     *
     * @param data      Text to sign
     * @param secretKey Secret key
     * @return HMAC
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeyException      If the key is invalid
     */
    private static byte[] calculateHMAC(byte[] data, SecretKey secretKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(secretKey);
        return hmac.doFinal(data);
    }

    /**
     * Verify the HMAC from a file
     *
     * @param texto     Text to sign
     * @param file      File with the HMAC
     * @param secretKey Secret key
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeyException      If the key is invalid
     */
    private static void verifyHMACFromFile(String texto, String file, SecretKey secretKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        // Calculate the HMAC
        byte[] hmac = calculateHMAC(texto.getBytes(), secretKey);

        //Read the HMAC from the file
        byte[] hmacFromFile = new byte[hmac.length];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(hmacFromFile);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        // Print the HMACs
        System.out.println("HMAC: " + new String(hmac));
        System.out.println("HMAC from file: " + new String(hmacFromFile));

        // Compare the HMACs
        String message = MessageDigest.isEqual(hmac, hmacFromFile)
                ? "The HMACs are the same"
                : "The HMACs are different";
        System.out.println(message);
    }
}
