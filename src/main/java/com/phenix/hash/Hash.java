package com.phenix.hash;

import jakarta.validation.constraints.NotNull;
import jakarta.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * Outils de hash.
 *
 * @author <a href="mailto:edouard128@hotmail.com">Edouard Jeanjean</a>
 */
public final class Hash {

    /**
     * On ne peut pas instancier la classe.
     */
    private Hash() throws Exception {
        throw new Exception("Cette classe ne peut pas être instanciée.");
    }

    /**
     * Les différents algorithme utilisable.
     */
    public enum Algorithme {
        /**
         * Algorithme de hash : MD5.
         */
        MD5("MD5");

        /**
         *
         */
        private final String valeur;

        /**
         *
         * @param valeur
         */
        private Algorithme(String valeur) {
            this.valeur = valeur;
        }

        /**
         *
         * @return
         */
        @Override
        public String toString() {
            return this.valeur;
        }
    }

    /**
     * Calcule le MD5 d'un fichier.
     *
     * @param fichier Le fichier à calculer le MD5.
     * @return MD5 du fichier.
     *
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    @NotNull
    public static String calculHash(@NotNull File fichier) throws IOException, NoSuchAlgorithmException {
        return calculHash(fichier, Algorithme.MD5);
    }

    /**
     * Calcule le hash d'un fichier.
     *
     * @param fichier Le fichier à calculer le hash.
     * @param algorithme Algorithme de calcule de hash.
     * @return Le hash du fichier.
     *
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    @NotNull
    public static String calculHash(@NotNull File fichier, @NotNull Algorithme algorithme) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithme.toString());
        md.update(Files.readAllBytes(fichier.toPath()));
        return DatatypeConverter.printHexBinary(md.digest()).toUpperCase();
    }

    /**
     * Retourne le hash en Base64 du hash SHA-1 d'un fichier.
     *
     * @param fichier Le fichier a faire le hash.
     * @return Le hash du fichier.
     *
     * @throws NoSuchAlgorithmException Erreur si l'algorithme n'est pas trouvé.
     * @throws IOException Erreur dans le flux.
     */
    @NotNull
    public static String hashCompact(@NotNull File fichier) throws NoSuchAlgorithmException, IOException {
        MessageDigest md5Digest = MessageDigest.getInstance("SHA-1");

        // Get file input stream for reading the file content
        FileInputStream fis = new FileInputStream(fichier);

        // Create byte array to read data in chunks
        byte[] byteArray = new byte[1024];
        int bytesCount;

        // Read file data and update in message digest
        while ((bytesCount = fis.read(byteArray)) != -1) {
            md5Digest.update(byteArray, 0, bytesCount);
        }

        // close the stream; We don't need it now.
        fis.close();

        // Get the hash's bytes
        byte[] bytes = md5Digest.digest();

        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Retourne le MD5, peut supporter des fichiers de plus de 2Go.
     *
     * @param fichier Le fichier.
     * @return Le MD5.
     *
     * @throws IOException
     */
    @NotNull
    public static String getMD5(@NotNull File fichier) throws IOException {
        try (InputStream is = Files.newInputStream(fichier.toPath())) {
            return DigestUtils.md5Hex(is);
        }
    }
}
