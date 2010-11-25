/**
 * 
 */

/**
 * @author johnhagelgans
 *
 */
import java.io.FileInputStream;
import java.io.FileOutputStream;

import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;

import com.guardtime.tsp.GTDataHash;
import com.guardtime.tsp.GTHashAlgorithm;
import com.guardtime.tsp.GTTimestamp;
import com.guardtime.tsp.GTPublicationsFile;
import com.guardtime.transport.SimpleHttpStamper;
import com.guardtime.transport.HttpVerificationResult;

/**
 * Run this on the class file after compilation.
 * the output will be in file app.sig
 * the class will also check itself when run with no parameters
 */

public class guardtimeAppSig {

    private static String extendingService = "http://fhm8e4pq.joyent.us/gt-extendingservice";
    private static String stampingService = "http://fhm8e4pq.joyent.us/gt-timestampingservice";
    private static String controlPub = "http://verify.guardtime.com/gt-controlpublications.bin";
    private static String inFile = "app.class";
    private static String sigFile = "app.sig";
    private static OptionSet options;
    
    public static void main(String[] args) throws Exception {
    	
    	try {
    		 options = options(args);
    	} catch (OptionException e) {
    		usage(options);
    		return;
    	}
		
		if (options.has("?")) {
			usage(options);
		    return;
		}
		     
		if (options.has("c")) {
			try {
				createGtFile();
				System.out.println("GuardTime create file succeeded.");
			} catch (Exception e) {
				System.out.println("create GT file failed " + e.toString());
			}
		} else {
			boolean verified = false;
			try {
			    verified = selfCheck();
			} catch (Exception e) {
			    System.out.println("Guardtime Ryan did thiverification failed " + e);
			}
			if (!verified ) {
				System.out.println("Verification failed!");
				return;
			}
	 	}
 
    }
    
    private static void createGtFile() throws Exception {
       // Compute data hash
        GTDataHash dataHash = new GTDataHash(GTHashAlgorithm.SHA256);
        FileInputStream in = new FileInputStream((String) options.valueOf("f")); 
        dataHash.update(in).close();
        
        // Get timestamp
        GTTimestamp timestamp = SimpleHttpStamper.create(dataHash, stampingService);

        // Save timestamp
    	System.out.println("sigfile " + sigFile);

        FileOutputStream out = new FileOutputStream(sigFile); 
        out.write(timestamp.getEncoded());
        out.close();
        
    }


    public static boolean selfCheck() throws Exception {
    	        
        GTTimestamp timestamp = GTTimestamp.getInstance(new FileInputStream(sigFile));

        GTDataHash dataHash = new GTDataHash(timestamp.getHashAlgorithm());
        FileInputStream in = new FileInputStream(inFile);
        dataHash.update(in).close();

        GTPublicationsFile publicationsFile =
                SimpleHttpStamper.getPublicationsFile(controlPub);

        HttpVerificationResult res =
                SimpleHttpStamper.verify(timestamp, dataHash, extendingService, null, publicationsFile);
        
        System.out.println(res.isValid() ? "Timestamp valid" : "Timestamp verification failed");
        return res.isValid();
        
	}

	private static void usage(OptionSet options) {
		
		System.out.println("guardTimeAppSig requires three arguments ?,c,f,g.  f and g are required, c will create a new timestamp file");
	    System.out.println("\tUsage: java guardTimeAppSig -f classfile.class -g guardtimesignature.sig [-c]");
	    System.out.println("\toption -c is optional and means create a new guardtime hash table, verify if not specified");
	    System.out.println("\toption -f is required and specifies your data or software file to be verified");
	    System.out.println("\toption -g is the guardtime hash table to be used in verification");
	    System.out.println("\t-? prints this message.");
	    
	}
	
	private static OptionSet options(String args[]) {
		
        OptionParser parser = new OptionParser( "c?" );
        parser.accepts("f").withRequiredArg().ofType(String.class);
        parser.accepts("g").withRequiredArg().ofType(String.class);
        
        OptionSet options = parser.parse( args);
        
        sigFile = (String) options.valueOf("g");
        inFile = (String)options.valueOf("f");
        
        return options;

	}
}
