/**
 * @author johnhagelgans
 *
 */
import java.io.*;

import com.guardtime.transport.HttpVerificationResult;
import com.guardtime.transport.SimpleHttpStamper;
import com.guardtime.tsp.GTDataHash;
import com.guardtime.tsp.GTHashAlgorithm;
import com.guardtime.tsp.GTPublicationsFile;
import com.guardtime.tsp.GTTimestamp;

import joptsimple.*;

public class guardtimeLogSigner {
	private static int size = 100000;
	private static Boolean verify = false;  // default mode is to generate timestamping information => false
	// otherwise program will check timestamping.
	
	private static String fileName;
	private static String iFileName;
	private static String oFileName;
	
    private static String extendingService = "http://fhm8e4pq.joyent.us/gt-extendingservice";
    private static String stampingService = "http://fhm8e4pq.joyent.us/gt-timestampingservice";
    private static String controlPub = "http://verify.guardtime.com/gt-controlpublications.bin";
    private static String inFile = "app.class";
    private static String sigFile = "app.sig";
    private static OptionSet options;
    		
	public static void main(String[] args) {
		try {
		   	try {
	    		 parseOptions(args);
	    	} catch (OptionException e) {
	    		usage();
	    		System.out.println(e);
	    		return;
	    	} catch (gtlsOptionException gto) {
	    		System.out.println(gto);
	    	}
	    	if (!verify) {
	    		createVerify();
	    	} else {
	    		verifyVerify();
	    	}
		} catch(Exception fe) {
			System.out.println(fe);
		}
	}

	private static void verifyVerify() {
		try {
			int mode = 0;
			int readLen = 0;
			FileInputStream veriFile = new FileInputStream(iFileName);
			try {
				byte firstByte[] = new byte[1];
				String fileName = "", range = "", tsSize = "";
				do {
					try {
						readLen = veriFile.read(firstByte,0,1);
					} catch (EOFException eof) {
							mode = 4;
							firstByte[0] = '\n';
					}
					if (readLen == -1) {
						mode = 4;
					} else {
						switch ((char)firstByte[0]) {
							case '[':
								fileName = readUntil(veriFile, ']');
								break;
							case '{':
								range = readUntil(veriFile, '}');
								break;
							case '(':
								tsSize = readUntil(veriFile, ')');
								break;
							case '\n':
								mode += 1;
								break;  // skip newlines
							default:
								System.out.println("Error in coding application");
						}
						if (mode == 3) {
							boolean success = processVerify(veriFile, fileName, range, tsSize);
							System.out.print("File: " + fileName + "  bytes: " + range);
							System.out.println((success == true) ? " checked ok": " FAILED!");
							mode = -1;
						}
					}
				} while (mode < 4);
						
			} catch (NumberFormatException nf) {
				System.out.println(nf);
			} finally {
			}
			
		} catch (IOException ioe) {
			System.out.println(ioe);
		}
	}
	
	private static boolean processVerify(FileInputStream veriFile, String fileName, String range, String tsSize) {
		boolean success = false;
		try {
			RandomAccessFile rStream =
				new RandomAccessFile(fileName, "r");
			int begin,end;
			String r[] = range.split("-");
			begin = Integer.parseInt(r[0]);
			end = Integer.parseInt(r[1]);

			byte ts[] = new byte[Integer.parseInt(tsSize)];
			byte b[] = new byte[end - begin];
			
			rStream.seek(begin);
			int readLen = rStream.read(b,0,end - begin);
			int keyLen = veriFile.read(ts,0,Integer.parseInt(tsSize));
			
			GTTimestamp timestamp = GTTimestamp.getInstance(ts);
		    GTDataHash dataHash = new GTDataHash(timestamp.getHashAlgorithm());
		    dataHash.update(b).close();
		    GTPublicationsFile publicationsFile =
	            SimpleHttpStamper.getPublicationsFile(controlPub);

	        HttpVerificationResult res =
	                SimpleHttpStamper.verify(timestamp, dataHash, extendingService, null, publicationsFile);
//	        System.out.println(res.isValid() ? "Timestamp valid" : "Timestamp verification failed");
	        success = res.isValid();
	 
			
		} catch (Exception e) {
			System.out.println(e);
		}
		return success;

	}


	private static String readUntil(FileInputStream file, char val) throws IOException {
		int size = 1;
		StringBuffer str = new StringBuffer(32);
		byte b[] = new byte[1];
		file.read(b,0,size);
		do {
			str.append((char)b[0]);
			file.read(b,0,size);
		} while (b[0] != val);
		return str.toString();
	}
	
	private static void createVerify() {
		String newline = "";
		try {
			RandomAccessFile rStream =
				new RandomAccessFile(fileName, "r");
			FileOutputStream out = new FileOutputStream(oFileName);
			try {
//				rStream.seek(size);
				int begin = 0;
				int readLen = size;
				do {
					byte b[] = new byte[size];
					byte data[] = null;
					try {
						readLen = rStream.read(b, 0, size);
						if (b.length != readLen) {
							data = new byte[readLen];
							for (int i = 0; i < readLen; i++) {
								data[i] = b[i];
							}
						} else {
							data = b;
						}
					} catch (EOFException eof) {
						readLen = b.length;
					} catch (IOException e) {
						System.out.println(e);
					}
					try {
						GTTimestamp ts = createGtStamp(data);
						String file = newline + "[" + fileName + "]";
						int len = begin + readLen;
						String sizes = "\n{" + begin + "-" + len + "}";
						String encodeLen = "\n(" + ts.getEncoded().length + ")";
						out.write(file.getBytes());
						out.write(sizes.getBytes());
						out.write(encodeLen.getBytes());
						out.write("\n".getBytes());
						out.write(ts.getEncoded());
						begin += readLen;
						newline = "\n";
					} catch(Exception e) {
						System.out.println(e);
					}
				} while (readLen == size);
			}catch (Exception e) {
				System.out.println(e);
			} finally { 
				rStream.close();
				out.close();
			}
			
		} catch(IOException e) {
				System.out.println(e);
		}
	}

	private static GTTimestamp createGtStamp(byte b[]) throws Exception {
		 
	    	GTDataHash dataHash = new GTDataHash(GTHashAlgorithm.SHA256);
	    	dataHash.update(b).close();
	        
	        // Get timestamp
	        return SimpleHttpStamper.create(dataHash, stampingService);
	        	       
	 }
	 
	private static void parseOptions(String args[]) throws gtlsOptionException {
		OptionParser parser = new OptionParser("s:l:i::o::?");
		options = parser.parse(args);

		if (!options.has("l")) {
			usage();
			throw new gtlsOptionException("Missing -l parameter");
		}
		if (!options.has("s")) {
			usage();
			throw new gtlsOptionException("Missing -s parameter");
		}
		if (!options.has("i") && !options.has("o") ||
				options.has("i") && options.has("o")) {
			usage();
			throw new gtlsOptionException("Must specify one of -i or -o parameter");
		}
		
		if (options.has("i")) {
			verify = true;
		}
		
		String sizeOpt = (String)options.valueOf("s");
		try {
			size = Integer.parseInt(sizeOpt.trim());
		} catch (NumberFormatException e) {
			usage();
			System.out.println(e);
			throw new gtlsOptionException("Option -l must be numeric: " + options.toString());
		}
		
		iFileName = (String)options.valueOf("i");
		oFileName = (String)options.valueOf("o");
		fileName = (String)options.valueOf("l");
	}
	
	private static void usage() {
		
		System.out.println("guardTimeLogSigner requires three arguments -l and -s are required, -o and -i are mutually exclusive, one is required.");
	    System.out.println("\tUsage: java guardTimeLogSigner -l logfile -s size [-i input] [-o output]");
	    System.out.println("\targument -l is required and is a log file name");
	    System.out.println("\targument -i is optional filename of input timestamp database");
	    System.out.println("\targument -o is optional filename of output timestamp database");
	    System.out.println("\targument -s is required and specifies the max amount of data which will be stamped");
	    System.out.println("\t-? prints this message.");
	    
	}
	

}
