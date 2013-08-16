package nics.crypto.proxy.afgh;

import nics.crypto.Tuple;
import it.unisa.dia.gas.jpbc.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;

import org.apache.commons.io.FileUtils;
/**
*
* @author Ali Sajjad
*/
public class Main {

	public static final int rBits = 256; //160;    // 20 bytes
	public static final int qBits = 1536; //512;    // 64 bytes
	public static final GlobalParameters global = new GlobalParameters(rBits, qBits);

	public static void main(String[] args) throws IOException, ClassNotFoundException 
	{
		// Secret keys

        Element sk_a = AFGH.generateSecretKey(global);

        Element sk_b = AFGH.generateSecretKey(global);

        // Public keys

        Element pk_a = AFGH.generatePublicKey(sk_a, global);

        Element pk_b = AFGH.generatePublicKey(sk_b, global);

        ElementPowPreProcessing pk_a_ppp = pk_a.pow();
        
        // Re-Encryption Key
        
        Element rk_a_b = AFGH.generateReEncryptionKey(pk_b, sk_a);

        // Plain Text
        
        File plainText = new File("plain.txt");
        
        log(plainText.getAbsolutePath());
        
        byte[] b = FileUtils.readFileToByteArray(plainText);
		
        Element m = AFGH.bytesToElement(b, global.getG2());
        
        Tuple CT = AFGH.secondLevelEncryption(m, pk_a_ppp, global);

        PairingPreProcessing e_ppp = global.getE().pairing(rk_a_b);
        
        // Re-Encryption into ciphertext CT
        
        Tuple CTT = AFGH.reEncryption(CT, rk_a_b, e_ppp);
        
        
        // Send to TTP
        
        sendToTTP(CTT);

        // Decryption by Bob

        Tuple CTTT = readFromTTP("CTT.ser");
        
        Element sk_b_inverse = sk_b.invert();
        
        Element mResult = AFGH.firstLevelDecryptionPreProcessing(CTTT, sk_b_inverse, global);
        
        FileUtils.writeByteArrayToFile(new File("result.txt"), mResult.toBytes());
	}
	
	private static void log(String str)
	{
		System.out.println(str);
	}
	
	private static void sendToTTP(Tuple t) throws IOException
	{
		ArrayList<byte[]> res = t.toBytes();
		FileOutputStream fout = new FileOutputStream("CTT.ser");
        ObjectOutputStream oos = new ObjectOutputStream(fout);
        oos.writeObject(res);
        oos.flush();
        oos.close();
        fout.flush();
        fout.close();
	}
	
	private static Tuple readFromTTP(String file) throws IOException, ClassNotFoundException
	{
		FileInputStream fin = new FileInputStream(file);
        ObjectInputStream ois = new ObjectInputStream(fin);
        @SuppressWarnings("unchecked")
		ArrayList<byte[]> CTTList = new ArrayList<byte[]>( (ArrayList<byte[]>) ois.readObject());
        ois.close();
        fin.close();
        
        Element[] elements = new Element[CTTList.size()];
        
        for (int i = 0; i < CTTList.size(); i++)
        {
        	elements[i] = AFGH.bytesToElement(CTTList.get(i), global.getG2());
        }
        return new Tuple(elements);
	}
}
