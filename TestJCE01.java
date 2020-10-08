import java.security.*;
import java.util.Arrays;
import javax.crypto.*;

// --------------------------------------------------
// Exemple d'utilisation du JCE
// Generation d'une paire de cles publique/privee
// --------------------------------------------------

class TestJCE01 {
    static PrivateKey priv;
    static PublicKey pub;
    private static void genererCles() {
		// Indications:
		//    - utiliser l'algo "SHA1PRNG" pour generer le nombre aleatoire
		//    - utiliser l'algo "RSA" pour generer la paire de cles
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			int bitsize = 1024;
			keyGen.initialize(bitsize, random);

			KeyPair pair = keyGen.generateKeyPair();
			priv = pair.getPrivate();
			pub = pair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
    }
	
    private static byte[] crypter(String msg) {
		// Indications:
		//    - utiliser la combinaison "RSA/ECB/PKCS1Padding" pour creer le Cipher
		//    - penser a convertir la String en byte[] via la methode getBytes() avant de chiffrer
		try {
			Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			enc.init(Cipher.ENCRYPT_MODE, priv);
			enc.update(msg.getBytes());
			return enc.doFinal();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			System.err.println(e);
		}
			return new byte[0];
    }
	
    private static String decrypter(byte[] buffer) {
		// Idem ci-dessus...
		try {
			Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			dec.init(Cipher.DECRYPT_MODE, pub);
			dec.update(buffer);
			return (new String(dec.doFinal()));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
			return "error";
    }
	
    public static void main(String[] args) {
		if (args.length<1)
			{
			System.out.println("Usage: java TestJCE01 <message>");
			System.exit(0);
			}

		String theMessage = args[0];
		genererCles();

		System.out.println("message initial = \""+theMessage+"\"");
		byte[] buf = crypter(theMessage);
		System.out.println("message crypte  = \""+ buf +"\"");
		String msg = decrypter(buf);
		System.out.println("message final   = \""+msg+"\"");
    }
}
