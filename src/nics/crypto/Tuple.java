package nics.crypto;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Arrays;

/**
 *
 * @author david
 */
public class Tuple{
	
	public Element[] tuple;

    public Tuple(Element ... t) {
        tuple = Arrays.copyOf(t, t.length);
    }

    public Tuple(Tuple t) {
        tuple = Arrays.copyOf(t.tuple, t.tuple.length);
    }

    public Element get(int i){
        if(i <= 0 || i > tuple.length || tuple[i-1]==null){
           return null;
        } else {
            return tuple[i-1].getImmutable();
        } 
    }

    @Override
    public String toString() {
        return Arrays.toString(tuple).replace('[', '<').replace(']', '>');
    }

    public String toString(String label) {
        StringBuilder s = new StringBuilder("<");
        int i = 1;
        for(Element e : tuple){
            s.append(label + i + " = " + e);
            i++;
        }
        s.deleteCharAt(s.length()-1);
        return s.append(">").toString();
    }

    public ArrayList<byte[]> toBytes()
    {

    	ArrayList<byte[]> result = new ArrayList<byte[]>();

        for(Element e : tuple){
            byte[] b = e.toBytes();
            result.add(b);
        }
        return result;
    }
}
