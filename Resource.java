public class Resource {

	private String resName;
	private long resTimeToLive;
	private long resType;
	private String resData;
	private String typeCode;
	
	public Resource(String rName, long rTTL, long rType, String rData) {
		this.resName = rName;
		this.resTimeToLive = rTTL;
		this.resType = rType;
		this.resData = rData;
	}
	
	public String getName() {
		return resName;
	}
	
	public long getTTL() {
		return resTimeToLive;
	}
	
	public long getType() {
		return resType;
	}
	
	public String getData() {
		return resData;
	}

	public String toString() {
		if ((int) resType == 1)
			typeCode = "A";
		else if ((int) resType == 2)
			typeCode = "NS";
		else if ((int) resType == 5)
			typeCode = "CN";
		else if ((int) resType == 28)
			typeCode = "AAAA";
		else
			typeCode = String.valueOf(resType);

		return String.format("       %-30s %-10d    %-4s %s", resName, resTimeToLive, typeCode, resData);
	}
}