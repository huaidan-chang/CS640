import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
	
	ServerSocket serverSocket;
	
	public Server(int port) {
		try {
			serverSocket = new ServerSocket(port);
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Error: I/O Exception when create serversocket");
			System.exit(1);
		}
	}
	
	
	public void startListening() {
		InputStream in = null;
		Socket clientSocket = null;
		 try {
			//Listen for a connection
			clientSocket = serverSocket.accept();
			//time when clientSocket is created
			long startTime = System.currentTimeMillis();
			
			//get client input
			in = clientSocket.getInputStream();
			byte[] buffer = new byte[1000];
			long readLen;
			long totalReadBytes = 0;
			while((readLen = in.read(buffer, 0, 1000)) != -1) {
				totalReadBytes += readLen;
			}
			
			long endTime = System.currentTimeMillis();
			long totalTime = endTime - startTime;
			long totalTimeSecond = totalTime/1000;
			
			//Calculate the rate
			double rate  = ((totalReadBytes*8.0)/(Math.pow(10, 6)))/totalTimeSecond;
			System.out.println("Server total time(s):" + totalTimeSecond);
			System.out.print("Server received= " + (totalReadBytes/1000) + " KB rate= " + String.format("%.3f", rate) + " Mbps");
			
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Error: I/O Exception when create serversocket startListening");
			System.exit(1);
		} finally {
			if(in != null) {
				try {
					in.close();
				} catch (IOException e) {
					e.printStackTrace();
					System.out.println("Error: I/O Exception when serversocket closing inputstream");
					System.exit(1);
				}
			}
			
			if(clientSocket != null) {
				try {
					//close connection
					clientSocket.close();
				} catch (IOException e) {
					e.printStackTrace();
					System.out.println("Error: I/O Exception when serversocket closing clientsocket");
					System.exit(1);
				}
			}
			
			if(serverSocket != null) {
				try {
					serverSocket.close();
				} catch (IOException e) {
					e.printStackTrace();
					System.out.println("Error: I/O Exception when serversocket closing serversocket");
					System.exit(1);
				}
			}
		}
	}
}
