package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		// check if the packet is IPv4
		if(etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("Drop: not IPv4!");
			System.out.println("----------------------------------");
			return;
		} else {
			// get the IPv4 header and cast result into IPv4
			IPv4 header = (IPv4)etherPacket.getPayload();
			short checkSumOri = header.getChecksum();
			System.out.println("checkSumOri:" + checkSumOri);
			// set checksum to zero before calculating checksum
			header.resetChecksum();
			byte[] serializedByte = header.serialize();
			
			// deserialize header to calculate checksum
			header.deserialize(serializedByte, 0, serializedByte.length);
			
			// get calculate checksum
			short checkSumCal = header.getChecksum();
			System.out.println("checkSumCal:" + checkSumCal);
			
			if(checkSumCal != checkSumOri) {
				System.out.println("Drop: checksum is incorrect!");
				System.out.println("----------------------------------");
				return;
			} else {
				byte ttl = header.getTtl();
				// decrement the IPv4 packet’s TTL by 1
				header.setTtl((byte)(ttl-1));
				
				if(header.getTtl() == (byte)0) {
					System.out.println("Drop: TTL is 0!");
					System.out.println("----------------------------------");
					return;
				} else {
					// set new header to ethernetPacket
					header.resetChecksum();
					serializedByte = header.serialize();
					header.deserialize(serializedByte, 0, serializedByte.length);
					etherPacket.setPayload(header);
					
					// foreach all interfaces on the router
					for(Iface iface: interfaces.values()) {
						//If the packet’s destination IP address exactly 
						//matches one of the interface’s IP addresses
						//drop
						if(header.getDestinationAddress() == iface.getIpAddress()) {
							System.out.println("Drop: equals to router's interface Ip!");
							System.out.println("----------------------------------");
							return;
						}
					}
					
					//IPv4 packets with a correct checksum, TTL > 1 (pre decrement), 
					//and a destination other than one of the router’s interfaces should be forwarded.
					
					// forwarding
					RouteEntry entry = routeTable.lookup(header.getDestinationAddress());
					if(entry == null) {
						System.out.println("Drop: no entry in routeTable!");
						System.out.println("----------------------------------");
						return;
					} else {
						// if the gatewayAddress is not zero means that the next hop is a router
						// thus the next hop ip is gatewayAddress
						// if the gatewayAddress is zero means that the interface directly connects to the router
						// thus the next hop ip is destinationAddress in header
						int nextHop = entry.getGatewayAddress() != 0 ? entry.getGatewayAddress() : header.getDestinationAddress();
						ArpEntry ae = arpCache.lookup(nextHop);
						if(ae == null) {
							System.out.println("Drop: no arpentry!");
							System.out.println("----------------------------------");
							return;
						} else {
							// set new destination MAC address for the Ethernet frame
							MACAddress newDestMac = ae.getMac();
							etherPacket.setDestinationMACAddress(newDestMac.toBytes());
							
							// The MAC address of the outgoing interface should be 
							// the new source MAC address for the Ethernet frame
							MACAddress newSrcMac = entry.getInterface().getMacAddress();
							etherPacket.setSourceMACAddress(newSrcMac.toBytes());
							
							// send packet
							sendPacket(etherPacket, entry.getInterface());
						}
					}
					
				}
			}
			
			
		}
		
		/********************************************************************/
	}
}
