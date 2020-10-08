import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

// --------------------------------------------------
// Exemple d'utilisation du JCE
// Generation d'une cle a partir d'un mot de passe (String)
// --------------------------------------------------

class TestJCE02 {
    private static final byte[] salt = {(byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c, (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99};
    private static final int count = 20;
    private static byte[] crypter(String password, String msg)	{
	// Indications:
	//    - utiliser "PBEWithMD5AndDES" pour le KeyFactory
	//    - utiliser "PBEWithMD5AndDES" pour le Cipher
	//    - penser a convertir la String en byte[] via la methode getBytes() avant de chiffrer

	try {
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, count);
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey passwordKey = kf.generateSecret(keySpec);

		Cipher c = Cipher.getInstance("PBEWithMD5AndDES");
		c.init(Cipher.ENCRYPT_MODE, passwordKey, paramSpec);
		// c.update(msg.getBytes());
		return c.doFinal(msg.getBytes());
	} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
		System.err.println(e);
	}
	return new byte[0];
    }
	
    private static String decrypter(String password, byte[] buffer) {
	// Idem ci-dessus...
	try {
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, count);
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey passwordKey = kf.generateSecret(keySpec);

		Cipher dec = Cipher.getInstance("PBEWithMD5AndDES");
		dec.init(Cipher.DECRYPT_MODE, passwordKey, paramSpec);
		// dec.update(buffer);
		return (new String(dec.doFinal(buffer)));
	} catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
		System.err.println(e);
	}
		return "error";
    }
	
    public static void main(String[] args) {
	if (args.length<2)
	    {
		System.out.println("Usage: java TestJCE02 <password> <message>");
		System.exit(0);
	    }
	
	String thePassword = args[0];
	String theMessage = args[1];
	
	System.out.println("message initial = \""+theMessage+"\"");
	byte[] buf = crypter(thePassword, theMessage);
	System.out.println("message crypte  = \""+ buf +"\"");
	String msg = decrypter(thePassword, buf);
	System.out.println("message final   = \""+msg+"\"");
    }
}
