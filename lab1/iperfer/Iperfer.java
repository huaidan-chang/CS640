
public class Iperfer {

	public static void main(String[] args) {
		//args count
		int argsCount = args.length;

		//args count at least 2
		if(argsCount < 2) {
			System.out.println("Error: invalid arguments");
			System.exit(1);
		}
		
		//Client or Server, the first argument should be c to represent client 
		//and s to represent server
		String mode = args[0];
		int port = 13000;
		String host = "";
		int time = 0;
		
		if(mode.equals("-s") || mode.equals("-c")) {
			if(mode.equals("-s")) {
				//Server
				//java Iperfer -s -p <listen port>
				if(args[1].equals("-p") && args.length == 3) {
					int portReturn = checkPortValid(args[2]);
					if(portReturn != -1) {
						port = portReturn;
						Server server = new Server(port);
						server.startListening();
					} else {
						System.out.println("Error: invalid arguments");
						System.exit(1);
					}
				} else {
					System.out.println("Error: invalid arguments");
					System.exit(1);
				}
			} else {
				//Client
				//java Iperfer -c -h <server hostname> -p <server port> -t <time>
				if(args[1].equals("-h") && args[3].equals("-p") && args[5].equals("-t") && args.length == 7) {
					host = args[2];
					int portReturn = checkPortValid(args[4]);
					if(portReturn != -1) {
						port = portReturn;
					} else {
						System.out.println("Error: invalid arguments");
						System.exit(1);
					}
					
					int timeReturn = checkTimeValid(args[6]);
					if(timeReturn != -1) {
						time = timeReturn;
					} else {
						System.out.println("Error: invalid arguments");
						System.exit(1);
					}
					
					Client client = new Client(host, port, time);
					client.startSending();
				} else {
					System.out.println("Error: invalid arguments");
					System.exit(1);
				}
			}
		} else {
			System.out.println("Error: invalid arguments");
			System.exit(1);
		}
	}
	
	//Check if the port is valid from 1024 to 65535
	public static int checkPortValid(String portStr) {
		try {
			int port = Integer.parseInt(portStr);
			if(port < 1024 || port > 65535) {
				return -1;
			} else {
				return port;
			}
		} catch(NumberFormatException e){
			return -1;
		} 
	}
	
	//Check if the time is valid
	public static int checkTimeValid(String timeStr) {
		try {
			int time = Integer.parseInt(timeStr);
			if(time < 0) {
				return -1;
			} else {
				return time;
			}
		} catch(NumberFormatException e){
			return -1;
		} 
	}

}
