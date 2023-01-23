import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;

public class Client {

	private String hostName;
	private int portNum;
	private int time;
	
	public Client(String hostName, int portNum, int time) {
		this.hostName = hostName;
		this.portNum = portNum;
		this.time = time;
	}
	
	public void startSending() {
		OutputStream out = null;
		Socket socket = null;
		try {
			//create connection to host
			socket = new Socket(hostName, portNum);
			long startTime = System.currentTimeMillis();
			byte[] data = new byte[1000];
        	Arrays.fill(data, (byte)0);
        	
        	//get outputstream from socket
        	out = socket.getOutputStream();
        	long timeMillis = time*1000;
        	long totalSendBytes = 0;
        	while(System.currentTimeMillis() - startTime < timeMillis) {
        		out.write(data);
        		out.flush();
        		totalSendBytes += data.length;
        	}
        	//calculate rate
    		double rate = ((totalSendBytes*8.0)/(Math.pow(10, 6)))/time;
    		System.out.println("Client total time(s):" + time);
    		System.out.print("Client sent= " + (totalSendBytes/1000) +" KB rate= " + String.format("%.3f", rate) + " Mbps");
		} catch (UnknownHostException e) {
	        System.err.println("Unkown Host: " + hostName);
	        System.exit(1);
	    } catch (IOException e) {
			e.printStackTrace();
		    System.err.println("Error: I/O Exception when clientsocket startSending");
		    System.exit(1);
		} finally {
			if(out != null) {
				try {
					out.close();
				} catch (IOException e) {
					e.printStackTrace();
					System.out.println("Error: I/O Exception when clientsocket closing outputstream");
					System.exit(1);
				}
			}
			
			if(socket != null) {
				try {
					//close connection
					socket.close();
				} catch (IOException e) {
					e.printStackTrace();
					System.out.println("Error: I/O Exception when clientsocket closing socket");
					System.exit(1);
				}
			}
		}
	}
}
