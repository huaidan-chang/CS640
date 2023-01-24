package edu.wisc.cs.sdn.simpledns;

import java.io.IOException;
import edu.wisc.cs.sdn.simpledns.packet.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SimpleDNS {
  private static final int BUFFER_SIZE = 8192;
  private static final int DNS_PORT = 53;
  private static final int PORT = 8053;

  static InetAddress rootServer;
  static List<Subnet> ec2Region;
 static  DatagramSocket clientSocket;
 
    public static void main(String[] args) throws IOException {
      System.out.println("DNS is ready...");
        String rootServerIp = args[1];
        String ec2Csv = args[3];
      
        // Set up DNS server
        rootServer = Inet4Address.getByName(rootServerIp);
        ec2Region = CSVParser.parse(ec2Csv);
        clientSocket=new DatagramSocket(PORT);
        while (true) {        
          DNS dnsPacket = receive_packet(clientSocket);
          if (dnsPacket.getOpcode() != DNS.OPCODE_STANDARD_QUERY) continue;
          handle_packet(dnsPacket);
      }   
    }
    
    
    private static void handle_packet(DNS content_packet) throws IOException {
      if (content_packet.getQuestions().size() == 0) return;
      switch (content_packet.getQuestions().get(0).getType()) {
          case DNS.TYPE_A:
          case DNS.TYPE_AAAA:
          case DNS.TYPE_NS:
          case DNS.TYPE_CNAME:
              if (content_packet.isRecursionDesired()) {
                  DNSQuestion question =  content_packet.getQuestions().get(0);
                  DNS packet = new QueryResolved(content_packet).recurse(rootServer, question);
                  packet.setQuery(false);
                  send_packet(clientSocket, packet);
              } else {
                  send_packet(clientSocket, resloved_DNS(rootServer, content_packet));
              }
              break;
          default:
              clientSocket.disconnect();
      }
  }
    
    private static DNS receive_packet(DatagramSocket socket) throws IOException {
      DatagramPacket datagramPacket = new DatagramPacket(new byte[BUFFER_SIZE], BUFFER_SIZE);
      socket.receive(datagramPacket);
      socket.connect(datagramPacket.getSocketAddress());
      return DNS.deserialize(datagramPacket.getData(), BUFFER_SIZE);
  }
    
    private static void send_packet(DatagramSocket socket, DNS dnsPacket) throws IOException {
      byte[] buffer = dnsPacket.serialize();
      socket.send(new DatagramPacket(buffer, buffer.length));
      socket.disconnect();
  }

  static DNS resloved_DNS(InetAddress dnsServer, DNS dnsPacket) throws IOException {
      try (DatagramSocket socket = new DatagramSocket(DNS_PORT)) {
          socket.connect(dnsServer, DNS_PORT);
          send_packet(socket, dnsPacket);
          DNS dns = receive_packet(socket);
          return dns;
      }
  }
}
    
class QueryResolved {
  private final int MAX_DEPTH = 64;
  private DNS originPacket;
  private int currentDepth = 0;
  
  // For authority and additional section
  List<DNSResourceRecord> pre_authorities = new ArrayList<>();
  List<DNSResourceRecord> pre_additionals = new ArrayList<>();
      
  QueryResolved(DNS origPacket) {
      this.originPacket = origPacket;
  }

  DNS recurse(InetAddress dnsServer, DNSQuestion question) throws IOException {
      DNS resultPacket = initPacket(question);
      if (currentDepth++ > MAX_DEPTH) return resultPacket;

      DNS responsePacket = SimpleDNS.resloved_DNS(dnsServer, resultPacket);
      
      // Check answer
      boolean found = false;
      for (DNSResourceRecord answer : responsePacket.getAnswers()) {
          if (answer.getType() == question.getType()) {
              resultPacket.addAnswer(answer);
              if (answer.getType() == DNS.TYPE_A || answer.getType() == DNS.TYPE_AAAA) {
                  String hostAddress = getAddr_record(answer).getHostAddress();
                  // add a TXT record to the answers 
                  addEc2TXT(resultPacket, hostAddress);
              }
              // if found answer
              found = true;
          } else if (answer.getType() == DNS.TYPE_CNAME) {
              resultPacket.addAnswer(answer);
          }
      }
      // if found answer
      if (found) return resultPacket;
     
      for (DNSResourceRecord answer : new ArrayList<>(resultPacket.getAnswers())) {
          if (!answer.getName().equals(question.getName()))
           
              resultPacket.getAnswers().remove(answer);
      }

      // Check CNAME
      for (DNSResourceRecord answer : responsePacket.getAnswers()) {
          if (answer.getType() != DNS.TYPE_CNAME) continue;
          if (!answer.getName().equals(question.getName())) continue;
          String name = ((DNSRdataName) answer.getData()).getName();
          DNS newResponse = recurse(SimpleDNS.rootServer, new DNSQuestion(name, question.getType()));
          for (DNSResourceRecord ans : newResponse.getAnswers()) {
              resultPacket.addAnswer(ans);
          }
          return resultPacket;
      }

      List<DNSResourceRecord> authorities = new ArrayList<>(responsePacket.getAuthorities());
      
      // Check Authorities in Additional Section
      for (DNSResourceRecord authority : responsePacket.getAuthorities()) {
          if (authority.getType() != DNS.TYPE_NS) continue;
          String name = ((DNSRdataName) authority.getData()).getName();
          InetAddress address = getServer_additional(name, responsePacket);
          // get previous authorities and additional
          pre_authorities=responsePacket.getAuthorities();
          pre_additionals=responsePacket.getAdditional();
       // if cannot find in the additional section
          if (address == null) 
              continue;
          // remove old authority
          authorities.remove(authority); 
          DNS newPacket = recurse(address, question);
          for (DNSResourceRecord answer : newPacket.getAnswers()) {
              if (answer.getType() == question.getType())
                // Add authority and additional
                newPacket.setAuthorities(pre_authorities);
                newPacket.setAdditional(pre_additionals);
                  return newPacket;
          }
      }

      // Find Authorities' IP from Root
      for (DNSResourceRecord authority : authorities) {
          if (authority.getType() != DNS.TYPE_NS) continue;
         
          String name = ((DNSRdataName) authority.getData()).getName();
          DNS newResponse = recurse(SimpleDNS.rootServer, new DNSQuestion(name, DNS.TYPE_A));
          InetAddress addr_ip = getARecord_packet(newResponse);
         
       // if cannot find the Authorities' IP from Root
          if (addr_ip == null) 
              continue;
          DNS newPacket = recurse(addr_ip, question);
          for (DNSResourceRecord answer : newPacket.getAnswers()) {
              if (answer.getType() == question.getType())
                  return newPacket;
          }
      }
      return originPacket;
  }

  private InetAddress getAddr_record(DNSResourceRecord answer) {
      return ((DNSRdataAddress) answer.getData()).getAddress();
  }

  private InetAddress getARecord_packet(DNS responseDNSPacket) {
      for (DNSResourceRecord answer : responseDNSPacket.getAnswers()) {
          if (answer.getType() != DNS.TYPE_A) continue;
          return getAddr_record(answer);
      }
      return null;
  }

  private InetAddress getServer_additional(String name, DNS responseDNSPacket) {
      for (DNSResourceRecord record : responseDNSPacket.getAdditional()) {
          if (record.getType() != DNS.TYPE_A) continue;
          if (!record.getName().equals(name)) continue;
          return ((DNSRdataAddress) record.getData()).getAddress();
      }
      return null;
  }

  // if address associated with an EC2 region, add a TXT record to the answers
  private void addEc2TXT(DNS returnDNSPacket, String hostAddress) {
      String hostName = originPacket.getQuestions().get(0).getName();
      for (Subnet subnet : SimpleDNS.ec2Region) {
          if (!subnet.check_range(hostAddress)) continue;
          DNSRdataString string = new DNSRdataString(subnet.result_ip(hostAddress));
          DNSResourceRecord record = new DNSResourceRecord(hostName, DNS.TYPE_TXT, string);
          returnDNSPacket.addAnswer(record);
          return;
      }
  }

  private DNS initPacket(DNSQuestion question) {
      DNS newPacket = originPacket.clone();
      newPacket.setQuestions(Collections.singletonList(question));
      newPacket.setRecursionDesired(false);
      return newPacket;
  }
}

class CSVParser {
  static List<Subnet> parse(String filename) throws IOException {
      List<String> lines = Files.readAllLines(Paths.get(filename), StandardCharsets.UTF_8);
      List<Subnet> result = new ArrayList<>();
      for (String line : lines) {
          result.add(new Subnet(line));
      }
      return result;
  }
}

class Subnet {
  private String region;
  private int ipValue;
  private int mask;

  public Subnet(String line) {
      String[] parts = line.split("[,/]");
      this.ipValue = handle_ip(parts[0]);
      this.mask = prefixToMask(Short.parseShort(parts[1]));
      this.region = parts[2];
  }

  private int prefixToMask(short prefix) {
      return -(1 << (32 - prefix));
  }

  private int handle_ip(String ipString) {
      String[] parts = ipString.split("\\.");
      int result = 0;

      for (String part : parts) {
          result <<= 8;
          result += Short.parseShort(part);
      }

      return result;
  }

  public boolean check_range(String ipString) {
      return (handle_ip(ipString) & this.mask) == (this.ipValue & this.mask);
  }

  public String result_ip(String ipString) {
      return this.region + '-' + ipString;
  }
}


    
    
    
    
    
