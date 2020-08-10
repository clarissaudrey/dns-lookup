import java.io.IOException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.lang.IllegalArgumentException;
import java.util.ArrayList;
import java.util.Random;

public class DNSQuery {
	private boolean tracingOn;
	private boolean IPV6Query;
	private DatagramSocket datagramSocket;
	private DatagramPacket queryDatagramPacket;
	private DatagramPacket responseDatagramPacket;
	private String saveNameServer;
	private String saveFQDN;
	private String saveCName = "";
	private ArrayList<String> lines = new ArrayList<String>();
	private int numOfQueryTried = 0;
	private int timeouts = 0;
	private boolean isNSResolved = false;
	
	// construct new DNSQuery object
	public DNSQuery(String inetAddressName, String fqdn, boolean tracingOn, boolean IPV6Query) throws SocketException {
		this.saveNameServer = inetAddressName;
		this.saveFQDN = fqdn;
		this.tracingOn = tracingOn;
		this.IPV6Query = IPV6Query;
		
		try {
			datagramSocket = new DatagramSocket();
			datagramSocket.setSoTimeout(5000);
		} catch (SocketException e) {
			System.out.println("Socket failed to initialize. Exitting..");
			System.exit(1);
		}
	}
	
	// start querying and return resolved IP address(es) (IPv4/IPv6) for the query requested if exists 
	// (max 30 queries to resolve a name)
	public String startQuery(String nameServerIP, String fullyQualifiedDomainName) throws Exception {
		numOfQueryTried += 1;
		if(numOfQueryTried < 30) {
			InetAddress inetAddressName = null;
			try {
				inetAddressName = InetAddress.getByName(nameServerIP);
			} catch (UnknownHostException e) {
				System.out.println("No IP address for the server could be found. Exitting..");
				System.exit(1);
			}

			String fqdn = fullyQualifiedDomainName;
			int fqdnLength = fqdn.length();
			byte[] queryPacket = new byte[fqdnLength + 2 + 16]; 
			long queryID = encodeQuery(fqdn, queryPacket); 
			queryDatagramPacket = new DatagramPacket(queryPacket, queryPacket.length, inetAddressName, 53);
			byte[] responsePacket = new byte[1024];
			responseDatagramPacket = new DatagramPacket(responsePacket, responsePacket.length);
			
			DNSResponse response = null;
			
			try {
				datagramSocket.send(queryDatagramPacket);
				datagramSocket.receive(responseDatagramPacket);
				response = new DNSResponse(responsePacket, fqdnLength);
			} catch (SocketTimeoutException timeoutException) {
				timeouts++;
				if(timeouts < 2) {
					startQuery(nameServerIP, fqdn);
				} else {
					if (tracingOn) {
						for (String line : lines) {
							System.out.println(line);
						}
					}
					if (IPV6Query)
						System.out.println(saveFQDN + " -2 AAAA 0.0.0.0");
					else
						System.out.println(saveFQDN + " -2 A 0.0.0.0");
					System.exit(0);
				}
			} catch (IllegalArgumentException e) {
				if (tracingOn) {
					for (String line : lines) {
						System.out.println(line);
					}
				}
				if (IPV6Query)
					System.out.println(saveFQDN + " -1 AAAA 0.0.0.0");
				else
					System.out.println(saveFQDN + " -1 A 0.0.0.0");
				System.exit(0);
			} catch (IOException e) {
				if (tracingOn) {
					for (String line : lines) {
						System.out.println(line);
					}
				}
				if (IPV6Query)
					System.out.println(saveFQDN + " -4 AAAA 0.0.0.0");
				else
					System.out.println(saveFQDN + " -4 A 0.0.0.0");
				System.exit(0);
			}

			updateLinesToBePrinted(fqdn, queryID, inetAddressName, response);

			// Resolving name server can lead to cases such as: 
			// (1) authorative & resolved to CName, (2) authorative & name server is resolved already, (3) authorative & found the answer, 
			// (4) nonauthorative & no valid IP match, then a corresponding name server needs to be resolved first,
			// (5) nonauthorative & there is a matched IP on name server and additional info
			if (response.isResponseAuthoritative() && response.hasCNameType()) { // Case (1)
				saveCName = response.getANData();
				return startQuery(saveNameServer, saveCName);
			}
			else if (response.isResponseAuthoritative() && isNSResolved)  // Case (2)
				return response.getANData();
			
			else if (response.isResponseAuthoritative() && !response.hasCNameType() && !isNSResolved) { // Case (3)
				ArrayList<String> foundAnswers = new ArrayList<String>();
				int answerTTL = 0;
				int answerTypeInt = 0;
				String answerType = "";
				try {
					foundAnswers = response.getAnswerIPAddresses();
					answerTTL = response.getANTimeToLive();
					answerTypeInt = response.getANType();
					if (answerTypeInt == 1)
						answerType = "A";
					else if (answerTypeInt == 28)
						answerType = "AAAA"; // all other types should be handled with exception
				} catch (NullPointerException e) {
					if (tracingOn) {
						for (String line : lines) {
							System.out.println(line);
						}
					}
					if (IPV6Query)
						System.out.println(saveFQDN + " -6 AAAA 0.0.0.0");
					else
						System.out.println(saveFQDN + " -6 A 0.0.0.0");
					System.exit(0);
				}
		
				if (tracingOn) {
					for (String line : lines) {
						System.out.println(line);
					}
				}
				for (String ip : foundAnswers) {
					System.out.println(saveFQDN + " " + answerTTL + " " + answerType + " " + ip);
				}

				datagramSocket.close();
				return null;
			}

			else if (!response.isResponseAuthoritative() && response.findAddressForNextLookup() == null) { // Case (4)
				isNSResolved = true;
				String resolvedNameServerIP = "";
				try {
					resolvedNameServerIP = startQuery(saveNameServer, response.getNSData());
				} catch (NullPointerException e) {
					if (tracingOn) {
						for (String line : lines) {
							System.out.println(line);
						}
					}
					if (IPV6Query)
						System.out.println(saveFQDN + " -4 AAAA 0.0.0.0");
					else
						System.out.println(saveFQDN + " -4 A 0.0.0.0");
					System.exit(0);
				}
				isNSResolved = false;
				startQuery(resolvedNameServerIP, saveFQDN);
			}

			else if (!response.isResponseAuthoritative() && response.findAddressForNextLookup() != null) // Case (5)
				return startQuery(response.findAddressForNextLookup(), fullyQualifiedDomainName);
		}
		else {
			if (tracingOn) {
				for (String line : lines) {
					System.out.println(line);
				}
			}
			if (IPV6Query)
				System.out.println(saveFQDN + " -3 AAAA 0.0.0.0");
			else
				System.out.println(saveFQDN + " -3 A 0.0.0.0");
			System.exit(0);
		}
		return null;
	}
	
	// Encode Question queries and return queryID
	private long encodeQuery(String fqdn, byte[] queryPacket) {
		Random queryID = new Random();
		queryPacket[0] = (byte) queryID.nextInt(126); // 2 bytes for queryID
		queryPacket[1] = (byte) queryID.nextInt(255);
		queryPacket[2] = (byte) 0; // 1 byte for QR,Opcode,AA,TC,RD
		queryPacket[3] = (byte) 0; // 1 byte for RA,Z,RCODE
		queryPacket[4] = (byte) 0; // 2 bytes for QDCount
		queryPacket[5] = (byte) 1;
		queryPacket[6] = (byte) 0; // 2 bytes for ANCount
		queryPacket[7] = (byte) 0;
		queryPacket[8] = (byte) 0; // 2 bytes for NSCount
		queryPacket[9] = (byte) 0;
		queryPacket[10] = (byte) 0; // 2 bytes for ARCount
		queryPacket[11] = (byte) 0;
		
		int tempIdx = 12;
		String[] splitQName = fqdn.split("\\.");
		for (int i=0; i<splitQName.length; i++) {
			String sectioniOfQName = splitQName[i];
			queryPacket[tempIdx++] = (byte) sectioniOfQName.length(); // 1 byte for each QName's section i length
			for (char character : sectioniOfQName.toCharArray()) {
				queryPacket[tempIdx++] = (byte) character; // QName's section i's length bytes
			}
		}
		queryPacket[tempIdx++] = (byte) 0; // 1 byte of 00 for end of QName
		if (IPV6Query && !isNSResolved) {
			queryPacket[tempIdx++] = (byte) 0; // 2 bytes for QType
			queryPacket[tempIdx++] = (byte) 0x1c;
		}
		else {
			queryPacket[tempIdx++] = (byte) 0;
			queryPacket[tempIdx++] = (byte) 1;
		}
		queryPacket[tempIdx++] = (byte) 0; // 2 bytes for QClass
		queryPacket[tempIdx++] = (byte) 1;
		
		return (0x0FFL & (long)queryPacket[0]) << 8 | (0x0FFL & (long)queryPacket[1]);
	}

	// Add lines to be printed in console
	private void updateLinesToBePrinted(String fqdn, long queryID, InetAddress inetAddressName, DNSResponse response) {
		if (fqdn.equals(saveFQDN) || fqdn.equals(saveCName)) {
			if (IPV6Query)
				lines.add("\n\nQuery ID     " + queryID + " " + fqdn + " AAAA " + " --> " + inetAddressName.getHostAddress());
			else
				lines.add("\n\nQuery ID     " + queryID + " " + fqdn + " A " + " --> " + inetAddressName.getHostAddress());
		}
		else {
			lines.add("\n\nQuery ID     " + queryID + " " + fqdn + " A " + " --> " + inetAddressName.getHostAddress());
		}
		lines.addAll(response.dumpResponse());
	}
}