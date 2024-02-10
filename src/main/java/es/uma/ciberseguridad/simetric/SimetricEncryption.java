package es.uma.ciberseguridad.simetric;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class SimetricEncryption {
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Security.setProperty("crypto.policy", "unlimited");

        String myName = "Andrés Samuel Podadera González";
        System.out.println("Name: " + myName);

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

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); //key size according to the requirement
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16]; // AES block size is 16 bytes
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

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

    private static byte[] readFromFile() throws IOException, ClassNotFoundException {
        FileInputStream fis = new FileInputStream("src/main/java/es/uma/ciberseguridad/simetric/encryptedFile.bin");
        ObjectInputStream ois = new ObjectInputStream(fis);
        byte[] encryptedBytesFromFile = (byte[]) ois.readObject();
        ois.close();
        fis.close();
        return encryptedBytesFromFile;
    }

    private static void writeToFile(byte[] encryptedBytes) throws IOException {
        FileOutputStream fos = new FileOutputStream("src/main/java/es/uma/ciberseguridad/simetric/encryptedFile.bin");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(encryptedBytes);
        oos.close();
        fos.close();
    }

    private static String decrypt(byte[] encryptedBytes, SecretKey secretKey, IvParameterSpec ivParams)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
