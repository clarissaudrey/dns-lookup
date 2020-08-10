import java.net.InetAddress;
import java.util.ArrayList;
import java.io.IOException;
import java.lang.IllegalArgumentException;

public class DNSResponse {
    private long queryID;
    private boolean authoritative = false;
    private byte[] DNSResponsePacket;
	private long ANCount = 0, NSCount = 0, ARCount = 0; 
    private Resource[] ANArray, NSArray, ARArray;
	private int currIdx = 12;

	public DNSResponse(byte[] responsePacket, int fqdnLen) throws IllegalArgumentException, IOException {        
        this.DNSResponsePacket = responsePacket;
	    
		queryID = ((long)DNSResponsePacket[0] & 0x0FFL) << 8 | ((long)DNSResponsePacket[1] & 0x0FFL);
		authoritative = ((DNSResponsePacket[2] >> 2) & 0x1) == 1;
		if ((((long)DNSResponsePacket[3] & 0x0FFL) & 0xf) == 3) {
			throw new IllegalArgumentException();
		} else if ((((long)DNSResponsePacket[3] & 0x0FFL) & 0xf) == 5) {
			throw new IOException();
		}
		
		ANCount = ((long)DNSResponsePacket[6] & 0x0FFL) << 8 | ((long)DNSResponsePacket[7] & 0x0FFL); 		
		NSCount = ((long)DNSResponsePacket[8] & 0x0FFL) << 8 | ((long)DNSResponsePacket[9] & 0x0FFL); 		
		ARCount = ((long)DNSResponsePacket[10] & 0x0FFL) << 8 | ((long)DNSResponsePacket[11] & 0x0FFL);
		
		currIdx += fqdnLen + 6;
		
		int i=0, j=0, k=0;
		if (ANCount > 0) {
			ANArray = new Resource[(int) ANCount];
			while (i<ANCount) { 
				ANArray[i] = createNewResource();
				i++;		
			}
		}
		if (NSCount > 0) {
			NSArray = new Resource[(int) NSCount];
			while (j<NSCount) { 
				NSArray[j] = createNewResource();
				j++;
			}
		}
		if (ARCount > 0) {
			ARArray = new Resource[(int) ARCount];
			while (k<ARCount) {
				ARArray[k] = createNewResource();
				k++;
			}
		}
	}

	// Create new Resource
	private Resource createNewResource() {
		Resource resource;
		
		String resourceName = getHostName();
		long resourceType = ((long)DNSResponsePacket[currIdx] & 0x0FFL) << 8 | 
							((long)DNSResponsePacket[currIdx+1] & 0x0FFL);
		currIdx += 4;
		long resourceTTL = ((long)DNSResponsePacket[currIdx] & 0x0FFL) << 24 | 
							((long)DNSResponsePacket[currIdx+1] & 0x0FFL) << 16 | 
							((long)DNSResponsePacket[currIdx+2] & 0x0FFL) << 8 | 
							((long)DNSResponsePacket[currIdx+3] & 0x0FFL);
		currIdx += 6;
		String resourceData = "";
		switch ((int)resourceType) {
			case 1:
				int i=0;
				while (i < 4) {
					String x = String.format("%d", 0x0FFL & (long)DNSResponsePacket[currIdx]);
					if (i != 3)
						x += ".";
					resourceData += x;
					currIdx++;
					i++;
				}
				break;
			case 28:
				byte[] IPv6Buffer = new byte[16];
				for(int j=0; j<16; j++) {
					IPv6Buffer[j] = DNSResponsePacket[currIdx];
					currIdx++;
				}
				for(int j=0; j<16; j+=2) {
					String IPv6Segment = String.format("%x", (((IPv6Buffer[j] & 0xFFL) << 8) | (IPv6Buffer[j+1] & 0xFFL)));
					if (j != 14)
						IPv6Segment += ":";
					resourceData += IPv6Segment;
				}
				break;
			case 2:
				resourceData = getHostName();
				break;
			case 5:
				resourceData = getHostName();
				break;
			default:
				resourceData = "----";
		}
		
		resource = new Resource(resourceName, resourceTTL, resourceType, resourceData);
		return resource;
    }
    
    // Parse host name of the server, of a resource data
	private String getHostName() {
		String word = "", nameSegment = "";
		int size = DNSResponsePacket[currIdx], i=0;
		
		if(size == 0)
			currIdx += 1;
		else {
			if(size >= 0) {
				currIdx += 1;
				while(i<size) {
					nameSegment += (char) DNSResponsePacket[currIdx++];
					i++;
				}
				word += nameSegment + "." + getHostName();
				if(!word.isBlank() && word.charAt(word.length()-1) == '.')
					word = word.substring(0, word.length() - 1);
			}
			else {
				long ptr = ((0x0FFL & (long)DNSResponsePacket[currIdx]) << 8 | 
							(0x0FFL & (long)DNSResponsePacket[currIdx+1])); 
				word = handleCompressedMessages((ptr & 0x03FFFL));
				currIdx += 2;
				if(!word.isBlank() && word.charAt(word.length()-1) == '.')
					word = word.substring(0, word.length() - 1);
			}
		}
		return word;
    }
    
    // Parse pointer to a word (using the offset)
	private String handleCompressedMessages(long idx) {
		String word = "", nameSegment = "";
		int size = DNSResponsePacket[(int) idx], i=0;

		if(size == 0) {
			// do nothing
		}
		else {
			if(size >= 0) {
				idx += 1;
				while(i<size) {
					nameSegment += (char) DNSResponsePacket[(int)idx++];
					i++;
				}
				word += nameSegment + "." + handleCompressedMessages(idx);
			}
			else {
				word = handleCompressedMessages(((0x0FFL & (long)DNSResponsePacket[(int)idx]) << 8 | 
									(0x0FFL & (long)DNSResponsePacket[(int)idx+1])) & 0x03FFF);	
			}
		}
		return word;
	}
    
	// When in trace mode you probably want to dump out all the relevant information in a response
	public ArrayList<String> dumpResponse() {
		ArrayList<String> lines = new ArrayList<String>();
		Resource resource;
		int i=0, j=0, k=0;
		
		lines.add("Response ID: " + queryID + " Authoritative = " + authoritative);
		lines.add("  Answers (" + ANCount + ")");
		if(ANCount > 0) {
			while(i<ANArray.length) {
				resource = ANArray[i];
				lines.add(resource.toString());
				i++;
			}
		}
		else if(ANCount == 0) {
			// do nothing
		}

		lines.add("  Nameservers (" + NSCount + ")");
		if(NSCount > 0) {
			while (j<NSArray.length) {
				resource = NSArray[j];
				lines.add(resource.toString());
				j++;
			}
		}
		else if(NSCount == 0) {
			// do nothing
		}

		lines.add("  Additional Information (" + ARCount + ")");
		if(ARCount > 0) {
			while(k<ARArray.length) {
				resource = ARArray[k];
				lines.add(resource.toString());
				k++;
			}
		}
		else if(ARCount == 0) {
			// do nothing
		}

		return lines;
	}
	
	// True if resource type is CNAME
	public boolean hasCNameType() {
		if (!isResponseAuthoritative() || ANCount <= 0)
			return false;
		else
			return (getANType() == 5);
	}

	// Returns authoritative code
	public boolean isResponseAuthoritative() {
		return authoritative;
	}
		
	// Get answer's TTL
	public int getANTimeToLive() {
		return (int) ANArray[0].getTTL();
	}

	// Get answer's type
	public int getANType() {
		return (int) ANArray[0].getType();
	}

	// Get Answer's IP address
	public String getANData() {
		return ANArray[0].getData();
	}

	// Get Name Server's IP address
	public String getNSData() {
		return NSArray[0].getData();
	}
	
	// Return an IPv4 address if authentication=false for next lookup
	public String findAddressForNextLookup() {
		if(ARCount == 0)
			return null;
		else {
			int i=0,j=0;
			while(i<NSCount) {
				while(j<ARCount) {
					Resource additionalRecord = ARArray[j]; 
					if (NSArray[i].getData().equals(additionalRecord.getName()) && additionalRecord.getType() == 1)
						return additionalRecord.getData();
					j++;
				}
				i++;
			}
		}
		return null;
	}
	
	// Get all the answer's IP addresses 
    public ArrayList<String> getAnswerIPAddresses() throws NullPointerException {
		ArrayList<String> answerIPAdressesList = new ArrayList<String>();
		if(ANCount == 0)
			throw new NullPointerException();
		int i=0;
		while(i<ANCount) {
			answerIPAdressesList.add(ANArray[i].getData());
			i++;
		}
		return answerIPAdressesList;
	}
}
