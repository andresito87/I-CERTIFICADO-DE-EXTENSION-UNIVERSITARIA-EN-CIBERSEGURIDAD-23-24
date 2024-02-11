package es.uma.ciberseguridad.simetric;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * This class shows how to use symmetric encryption to encrypt and decrypt a text.
 * The text is encrypted using AES algorithm in CTR mode and PKCS5Padding padding.
 * The key and IV are generated randomly.
 * The encrypted text is saved in a file named A.bin.
 *
 * @author Andrés Samuel Podadera González
 * @version 1.0
 * @since 1.0
 */
public class SimetricEncryption {
    public static void main(String[] args) {
        
        // Add BouncyCastle as a Security Provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Unlimited cryptography policy
        Security.setProperty("crypto.policy", "unlimited");

        // Print my name, text to encrypt
        String myName = "Andrés Samuel Podadera González";
        System.out.println("Name: " + myName);

        // Convert my name to bytes using UTF-8 encoding
        byte[] myNameBytes = myName.getBytes(StandardCharsets.UTF_8);

        try {
            // Generate secret key and IV
            SecretKey secretKey = generateSecretKey();
            IvParameterSpec ivParams = generateIV();

            // Encrypt and write to file
            byte[] encryptedBytes = encrypt(myNameBytes, secretKey, ivParams);
            writeToFile(encryptedBytes);

            // Read from file, decrypt and print
            byte[] encryptedBytesFromFile = readFromFile();
            String decryptedName = decrypt(encryptedBytesFromFile, secretKey, ivParams);
            System.out.println("Decrypted name: " + decryptedName);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    /**
     * This method generates a secret key for AES algorithm.
     *
     * @return SecretKey object
     * @throws NoSuchAlgorithmException If the algorithm is not available
     */
    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); //key size according to the requirement
        return keyGenerator.generateKey();
    }

    /**
     * This method generates an IV for AES algorithm.
     *
     * @return IvParameterSpec object
     */
    private static IvParameterSpec generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16]; // AES block size is 16 bytes
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    /**
     * This method encrypts a text using a secret key and an IV.
     *
     * @param plaintext the text to encrypt
     * @param secretKey the secret key
     * @param ivParams  the IV
     * @return the encrypted text
     * @throws NoSuchPaddingException             if the padding is not available
     * @throws NoSuchAlgorithmException           if the algorithm is not available
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid
     * @throws InvalidKeyException                if the key is invalid
     * @throws BadPaddingException                if the padding is bad
     * @throws IllegalBlockSizeException          if the block size is illegal
     */
    private static byte[] encrypt(byte[] plaintext, SecretKey secretKey, IvParameterSpec ivParams)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
        return cipher.doFinal(plaintext);
    }

    /**
     * This method reads the encrypted text from a file.
     *
     * @return the encrypted text
     * @throws IOException            if an I/O error occurs
     * @throws ClassNotFoundException if the class of the object is not found
     */
    private static byte[] readFromFile() throws IOException, ClassNotFoundException {
        FileInputStream fis = new FileInputStream("src/main/java/es/uma/ciberseguridad/simetric/A.bin");
        ObjectInputStream ois = new ObjectInputStream(fis);
        byte[] encryptedBytesFromFile = (byte[]) ois.readObject();
        ois.close();
        fis.close();
        return encryptedBytesFromFile;
    }

    /**
     * This method writes the encrypted text to a file.
     *
     * @param encryptedBytes the encrypted text
     * @throws IOException if an I/O error occurs
     */
    private static void writeToFile(byte[] encryptedBytes) throws IOException {
        FileOutputStream fos = new FileOutputStream("src/main/java/es/uma/ciberseguridad/simetric/A.bin");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(encryptedBytes);
        oos.close();
        fos.close();
    }

    /**
     * This method decrypts a text using a secret key and an IV.
     *
     * @param encryptedBytes the encrypted text
     * @param secretKey      the secret key
     * @param ivParams       the IV
     * @return the decrypted text
     * @throws NoSuchPaddingException             if the padding is not available
     * @throws NoSuchAlgorithmException           if the algorithm is not available
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid
     * @throws InvalidKeyException                if the key is invalid
     * @throws BadPaddingException                if the padding is bad
     * @throws IllegalBlockSizeException          if the block size is illegal
     */
    private static String decrypt(byte[] encryptedBytes, SecretKey secretKey, IvParameterSpec ivParams)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException {
        Cipher decipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
        byte[] decryptedBytes = decipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
