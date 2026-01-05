import java.io.*;
import java.beans.XMLDecoder;

class VulnerableApp {
    public void deserialize(InputStream in) {
        try {
            // Vulnerable: ObjectInputStream
            ObjectInputStream ois = new ObjectInputStream(in);
            Object o = ois.readObject();

            // Vulnerable: XMLDecoder
            XMLDecoder decoder = new XMLDecoder(in);
            Object result = decoder.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
