package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import java.util.HashMap;
import java.util.Map;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device {
  class entryTable {

    public Iface iface;
    public long time;

    public entryTable(Iface iface, long time) {
      this.iface = iface;
      this.time = time;
    }

    public long getTime() {
      return time;
    }

    public void setTime(long time) {
      this.time = time;
    }


    public Iface getInterface() {
      return iface;
    }

    public void setInterface(Iface newIface) {
      this.iface = newIface;
    }

  }

  HashMap<Object, entryTable> switchTable = new HashMap<Object, entryTable>();

  /**
   * Creates a router for a specific host.
   * 
   * @param host hostname for the router
   */
  public Switch(String host, DumpFile logfile) {
    super(host, logfile);
  }

  /**
   * Handle an Ethernet packet received on a specific interface.
   * 
   * @param etherPacket the Ethernet packet that was received
   * @param inIface     the interface on which the packet was received
   */
  public void handlePacket(Ethernet etherPacket, Iface inIface) {
    System.out.println("*** -> Received packet: " + etherPacket.toString().replace("\n", "\n\t"));

    /********************************************************************/
    /* TODO: Handle packets */

    String source_MAC = etherPacket.getSourceMAC().toString();
    String destinaiton_MAC = etherPacket.getDestinationMAC().toString();

    if (switchTable.containsKey(source_MAC)) {

      // If the source MAC already existed, then set the entry time
      switchTable.get(source_MAC).setTime(System.currentTimeMillis());


    } else {
      // Create new entry row
      entryTable newE = new entryTable(inIface, System.currentTimeMillis());
      
      // Learn source MAC
      switchTable.put(source_MAC, newE);
    }

    // If the destination MAC already existed
    if (switchTable.containsKey(destinaiton_MAC)) {

  
      entryTable e = switchTable.get(destinaiton_MAC);

      Iface targetInterface = e.getInterface();
      
      long currTime = System.currentTimeMillis();
   
      // if timeout, remove the entry
      if ((currTime - e.getTime()) / 1000 > 15) {
    
        // Remove that entry
        switchTable.remove(destinaiton_MAC);
        // Broacast to all hosts
        broacastToHosts(inIface, etherPacket);
      } else {
   
        sendPacket(etherPacket, targetInterface);
      }
    }
    else {
      broacastToHosts(inIface, etherPacket);
    }
  }


/**
 * Broacast to each host
 * @param inIface the interface on which the packet should go forward
 * @param etherPacket the Ethernet packet
 */
  public void broacastToHosts(Iface inIface, Ethernet etherPacket){
      Map<String, Iface> map = getInterfaces();

      // Broacast to all hosts
      for(String name : map.keySet()){

          Iface broacast = map.get(name);
          // In order to find correct interface, send packet to all interfaces
          if(broacast.getName().compareTo(inIface.getName()) != 0){            
              sendPacket(etherPacket, broacast);
          }
      }
  }
}
