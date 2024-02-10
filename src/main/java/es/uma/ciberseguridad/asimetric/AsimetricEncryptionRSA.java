package es.uma.ciberseguridad.asimetric;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class AsimetricEncryptionRSA {
    public static void main(String[] args) throws Exception {
        // Generar un par de claves RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Tamaño de la clave RSA
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Texto a firmar
        String texto = "Tu nombre y apellidos";

        // Inicializar objeto para firmar
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(texto.getBytes());

        // Firmar el texto
        byte[] firma = signature.sign();

        // Guardar la firma en un archivo binario
        try (FileOutputStream fos = new FileOutputStream("src/main/java/es/uma/ciberseguridad/asimetric/firma.bin")) {
            fos.write(firma);
        }catch (IOException e){
            System.out.println("Error: " + e.getMessage());
        }
    }
    
}



