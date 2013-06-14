package nics.crypto.proxy.afgh;

import nics.crypto.Tuple;
import it.unisa.dia.gas.jpbc.*;
import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
/**
*
* @author Ali Sajjad
*/
public class ACDC3Main {

	public static void main(String[] args) throws IOException 
	{
		int rBits = 256; //160;    // 20 bytes
        int qBits = 1536; //512;    // 64 bytes

        GlobalParameters global = new GlobalParameters(rBits, qBits);
        
        // Secret keys

        Element sk_a = AFGH.generateSecretKey(global);

        Element sk_b = AFGH.generateSecretKey(global);
        
        Element sk_T = AFGH.generateSecretKey(global);

        // Public keys

        Element pk_a = AFGH.generatePublicKey(sk_a, global);

        Element pk_b = AFGH.generatePublicKey(sk_b, global);
        
        Element pk_T = AFGH.generatePublicKey(sk_T, global);

        ElementPowPreProcessing pk_a_ppp = pk_a.pow();
        
        // Re-Encryption Key

        Element rk_a_T = AFGH.generateReEncryptionKey(pk_T, sk_a);
        
        Element rk_T_b = AFGH.generateReEncryptionKey(pk_b, sk_T);

        // Plain Text
        
        File plainText = new File("plain.txt");
        
        log(plainText.getAbsolutePath());
        
        byte[] b = FileUtils.readFileToByteArray(plainText);
		
        Element m1File = AFGH.bytesToElement(b, global.getG2());
        
        // Encryption into ciphertext c_a
        
        Tuple c_aFile = AFGH.secondLevelEncryption(m1File, pk_a_ppp, global);
        
        // Send c_aFile to TTP ???

        PairingPreProcessing e_ppp = global.getE().pairing(rk_a_T);
        
        // Re-Encryption into ciphertext c_T
        
        Tuple c_TFile = AFGH.reEncryption(c_aFile, rk_a_T, e_ppp);
        
        // Decryption by TTP ???
        
        Element sk_T_inverse = sk_T.invert();
        
        Element mTFile = AFGH.firstLevelDecryptionPreProcessing(c_TFile, sk_T_inverse, global);
        
        //String result = new String(m2.toBytes()).trim();
        
        FileUtils.writeByteArrayToFile(new File("TTP.txt"), mTFile.toBytes());
        
        // Re-Encryption into ciphertext c_b
        
        PairingPreProcessing e_pppT = global.getE().pairing(rk_T_b);
        
        Tuple c_bFile = AFGH.reEncryption(c_TFile, rk_T_b, e_pppT);

        // Decryption by Bob
        
        Element sk_b_inverse = sk_b.invert();
        
        //Element m2 = AFGH.firstLevelDecryptionPreProcessing(c_b, sk_b_inverse, global);
        
        Element m2File = AFGH.firstLevelDecryptionPreProcessing(c_bFile, sk_b_inverse, global);
        
        //String result = new String(m2.toBytes()).trim();
        
        FileUtils.writeByteArrayToFile(new File("result.txt"), m2File.toBytes());
        
        //log(result);

	}
	
	private static void log(String str)
	{
		System.out.println(str);
	}

}
