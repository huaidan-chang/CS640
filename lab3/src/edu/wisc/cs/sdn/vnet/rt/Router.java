package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;
	// arp queue
	private Map<Integer, List<Ethernet>> arpQueue;

	// ICMP type
	enum ICMPType {
		TIME_EXCEEDED, DST_NET_UNREACHABLE, DST_HOST_UNREACHABLE, DST_PORT_UNREACHABLE, ECHO_REPLY;
	}

	// RIP
	private Map<Integer, RipEntryData> ripMap;

	enum RIPType {
		RIP_REQ, RIP_RESP, RIP_REQ_UNSOLICITED;
	}

	// Destination Ethernet address(=broadcast MAC address)
	private final String RIP_MAC_BROADCAST = "ff:ff:ff:ff:ff:ff";
	// Destination IP address (= multicast IP address)
	private final String RIP_IP_MULTICAST = "224.0.0.9";

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpQueue = new ConcurrentHashMap<Integer, List<Ethernet>>();
		this.ripMap = new ConcurrentHashMap<Integer, RipEntryData>();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
			System.err.println("Error setting up routing table from file " + routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * 
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file " + arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
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

		switch (etherPacket.getEtherType()) {
		case Ethernet.TYPE_IPv4:
			IPv4 ip = (IPv4) etherPacket.getPayload();
			if (IPv4.toIPv4Address(RIP_IP_MULTICAST) == ip.getDestinationAddress()) {
				if (IPv4.PROTOCOL_UDP == ip.getProtocol()) {
					UDP udp = (UDP) ip.getPayload();
					if (UDP.RIP_PORT == udp.getDestinationPort()) {
						RIPv2 rip = (RIPv2) udp.getPayload();
						this.handleRipPacket(rip.getCommand(), etherPacket, inIface);
						break;
					}
				}
			}

			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		for (Iface iface : this.interfaces.values()) {
			arpCache.insert(iface.getMacAddress(), iface.getIpAddress());
		}

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum) {
			return;
		}

		// Check TTL
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if (0 == ipPacket.getTtl()) {
			sendICMPMsg(etherPacket, inIface, ICMPType.TIME_EXCEEDED);
			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				// If Protocol is TCP or UDP
				byte protocol = ipPacket.getProtocol();
				if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP) {
					sendICMPMsg(etherPacket, inIface, ICMPType.DST_PORT_UNREACHABLE);
				} else if (protocol == IPv4.PROTOCOL_ICMP) {
					ICMP icmpPacket = (ICMP) ipPacket.getPayload();
					// check if the ICMP message is an echo request
					// (i.e., the type field in the ICMP header equals 8).
					if (icmpPacket.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
						sendICMPMsg(etherPacket, inIface, ICMPType.ECHO_REPLY);
					}
				}
				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch) {
			sendICMPMsg(etherPacket, inIface, ICMPType.DST_NET_UNREACHABLE);
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) {
			return;
		}

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {
			// sendICMPMsg(etherPacket, inIface, ICMPType.DST_HOST_UNREACHABLE);
			sendArpRequest(etherPacket, inIface, outIface, nextHop);
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}

	/**
	 * ============ICMP================================
	 */

	/**
	 * send ICMP Message
	 * 
	 * @param etherPacket
	 * @param inIface
	 * @param type
	 */
	private void sendICMPMsg(Ethernet etherPacket, Iface inIface, ICMPType type) {
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		// Source MAC is the interface on which the original packet arrived
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		// get the IPv4 header and cast result into IPv4
		IPv4 ipHeader = (IPv4) etherPacket.getPayload();
		int srcAddr = ipHeader.getSourceAddress();
		RouteEntry bestMatch = this.routeTable.lookup(srcAddr);
		// If no entry matched, do nothing
		if (null == bestMatch) {
			return;
		}

		// If no gateway, then nextHop is original IP sourceAddress
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = srcAddr;
		}

		// Set original IP source MAC address as destination in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {
			sendArpRequest(etherPacket, inIface, inIface, nextHop);
			return;
		}

		ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		// set to the source IP of the original packet
		ip.setDestinationAddress(srcAddr);

		byte[] dataByteArr = null;

		if (type == ICMPType.ECHO_REPLY) {
			// the source IP in the IP header should be set to the destination IP
			// from the IP header in the echo request.
			ip.setSourceAddress(ipHeader.getDestinationAddress());

			// ICMP payload from request
			ICMP requestICMP = (ICMP) ipHeader.getPayload();
			dataByteArr = requestICMP.getPayload().serialize();

		} else {
			// set to the IP address of the interface on which the original packet arrived
			ip.setSourceAddress(inIface.getIpAddress());
			// The payload that follows the ICMP header must contain:
			// (1) 4 bytes of padding
			// (2) the original IP header from the packet that triggered the error message
			// (3) the 8 bytes following the IP header in the original packet.

			int ipHeaderLen = ipHeader.getHeaderLength() * 4;
			dataByteArr = new byte[4 + ipHeaderLen + 8];
			// padding 4 bytes
			Arrays.fill(dataByteArr, 0, 4, (byte) 0);

			// the original IP header from the packet that triggered the error message
			// the 8 bytes following the IP header in the original packet
			byte[] ipHeaderByte = ipHeader.serialize();
			for (int i = 0; i < ipHeaderLen + 8; i++) {
				dataByteArr[i + 4] = ipHeaderByte[i];
			}

		}

		ICMP icmp = new ICMP();
		switch (type) {
		case TIME_EXCEEDED:
			icmp.setIcmpType((byte) 11);
			icmp.setIcmpCode((byte) 0);
			break;
		case DST_NET_UNREACHABLE:
			icmp.setIcmpType((byte) 3);
			icmp.setIcmpCode((byte) 0);
			break;
		case DST_HOST_UNREACHABLE:
			icmp.setIcmpType((byte) 3);
			icmp.setIcmpCode((byte) 1);
			break;
		case DST_PORT_UNREACHABLE:
			icmp.setIcmpType((byte) 3);
			icmp.setIcmpCode((byte) 3);
			break;
		case ECHO_REPLY:
			icmp.setIcmpType((byte) 0);
			icmp.setIcmpCode((byte) 0);
			break;
		default:
			return;
		}

		Data data = new Data(dataByteArr);
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		sendPacket(ether, inIface);
	}

	/**
	 * ============ICMP================================
	 */

	/**
	 * ============ARP================================
	 */

	/**
	 * 
	 * @param etherPacket
	 * @param inIface
	 */
	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
		ARP arpPacket = (ARP) etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		short opCode = arpPacket.getOpCode();
		if (opCode == ARP.OP_REQUEST) {
			if (targetIp == inIface.getIpAddress()) {
				Ethernet arpReply = setArpPacket(etherPacket, inIface, ARP.OP_REPLY, 0);
				sendPacket(arpReply, inIface);
			} else {
				return;
			}
		} else if (opCode == ARP.OP_REPLY) {
			// add entry to ARP cache// add an entry to the ARP cache
			// the sender hardware address and sender protocol address fields
			MACAddress mac = new MACAddress(arpPacket.getSenderHardwareAddress());
			int ip = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress());
			arpCache.insert(mac, ip);

			// dequeue any waiting packets
			// fill in the correct destination MAC address
			// send those packets out the interface on which the ARP reply arrived
			synchronized (arpQueue) {
				List<Ethernet> dequeue = arpQueue.get(ip);
				if (dequeue != null) {
					for (Ethernet ether : dequeue) {
						ether.setDestinationMACAddress(arpPacket.getSenderHardwareAddress());
						sendPacket(ether, inIface);
					}
				}
			}
		}

	}

	private Ethernet setArpPacket(Ethernet etherPacket, Iface inIface, short opCode, int ip) {
		Ethernet ether = new Ethernet();
		// construct Ethernet header
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		// construct ARP header
		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte) 4);

		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		if (opCode == ARP.OP_REPLY) {
			ARP arpPacket = (ARP) etherPacket.getPayload();
			// set to the source MAC address of the original packet
			ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
			arp.setOpCode(ARP.OP_REPLY);
			// set to the sender hardware address from the original packet
			arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
			// set to the sender protocol address from the original packet
			arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
		} else if (opCode == ARP.OP_REQUEST) {
			// Destination MAC address — set to the broadcast MAC address FF:FF:FF:FF:FF:FF
			ether.setDestinationMACAddress(Ethernet.toMACAddress("FF:FF:FF:FF:FF:FF"));
			arp.setOpCode(ARP.OP_REQUEST);
			// set to 0
			arp.setTargetHardwareAddress(Ethernet.toMACAddress("00:00:00:00:00:00"));
			// set to the IP address whose associated MAC address we want
			arp.setTargetProtocolAddress(ip);
		}

		ether.setPayload(arp);
		return ether;
	}

	private void sendArpRequest(final Ethernet etherPacket, final Iface inIface, final Iface outIface, final int ip) {
		synchronized (arpQueue) {
			if (arpQueue.containsKey(ip)) {
				// add the packet to the queue
				arpQueue.get(ip).add(etherPacket);
			} else {
				List<Ethernet> newQueue = new ArrayList<Ethernet>();
				newQueue.add(etherPacket);
				arpQueue.put(ip, newQueue);
				Timer timer = new Timer();
				TimerTask arpTask = new TimerTask() {
					int count = 0;

					@Override
					public void run() {
						try {
							if (arpCache.lookup(ip) != null) {
								this.cancel();
							} else {
								// continue to send ARP requests every second until your router either
								// receives a corresponding ARP reply
								// or you have sent the same ARP request 3 times.
								if (count > 2) {
									List<Ethernet> removeQueue = arpQueue.get(ip);
									arpQueue.remove(ip);
									for (Ethernet ether : removeQueue) {
										// before dropping each packet, you should generate a destination host
										// unreachable message.
										sendICMPMsg(ether, inIface, ICMPType.DST_HOST_UNREACHABLE);
									}
									this.cancel();
								} else {
									Ethernet arpRequest = setArpPacket(etherPacket, inIface, ARP.OP_REQUEST, ip);
									sendPacket(arpRequest, outIface);
									count++;
								}
							}
						} catch (Exception e) {
							e.printStackTrace(System.out);
							this.cancel();
						}
					}
				};
				timer.schedule(arpTask, 0, 1000);
			}
		}
	}

	/**
	 * ============ARP================================
	 */

	/**
	 * ============RIP================================
	 */

	// For RIP
	class RipEntryData {
		protected int address, mask, nextHop, metric;
		protected long timestamp;

		// Collect RIP packet entry data
		public RipEntryData(int address, int mask, int nextHop, int metric, long timestamp) {
			this.address = address;
			this.mask = mask;
			this.nextHop = nextHop;
			this.metric = metric;
			this.timestamp = timestamp;
		}
	}

	/**
	 * Initialize RIP
	 */
	public void initializeRIP() {

		// Send a RIP request out of all of the router’s interfaces when RIP is
		// initialized.
		for (Iface iface : this.interfaces.values()) {
			int mask = iface.getSubnetMask();

			// generate subnet
			int subnet = mask & iface.getIpAddress();
			ripMap.put(subnet, new RipEntryData(subnet, mask, 0, 0, -1));
			// Cost with 0
			routeTable.insert(subnet, 0, mask, iface);

			// Send a RIP request out of all of the router’s interfaces when RIP is
			// initialized.
			sendRip(RIPType.RIP_REQ, null, iface);
		}

		// Send an unsolicited RIP response out all of the router’s interfaces every 10
		// seconds
		TimerTask unsolicitedRipTask = new TimerTask() {
			public void run() {
				// Broadcast to all interfaces
				for (Iface iface : interfaces.values()) {
					sendRip(RIPType.RIP_REQ_UNSOLICITED, null, iface);
				}
			}
		};

		// Time out route table entries for which an update has not been received for
		// more than 30
		// seconds.
		TimerTask timeOutTask = new TimerTask() {
			public void run() {
				for (RipEntryData entry : ripMap.values()) {
					if (entry.timestamp != -1) {
						// If more than 30 sec
						if (System.currentTimeMillis() - entry.timestamp >= 30000) {
							int subnet = entry.address & entry.mask;
							// remove it
							ripMap.remove(subnet);
							routeTable.remove(entry.address, entry.mask);
						}
					}
				}
			}
		};

		// Set the timer
		Timer timer = new Timer(true);
		timer.schedule(unsolicitedRipTask, 0, 10000);
		timer.schedule(timeOutTask, 0, 1000);
	}

	/**
	 * Deal with RIP packet
	 * 
	 * @param type        request or response
	 * @param etherPacket
	 * @param inIface     interface of router
	 */
	private void handleRipPacket(byte type, Ethernet etherPacket, Iface inIface) {
		switch (type) {
		// if receive request
		case RIPv2.COMMAND_REQUEST:
			sendRip(RIPType.RIP_RESP, etherPacket, inIface);
			break;

		// if receive response
		case RIPv2.COMMAND_RESPONSE:
			IPv4 ip = (IPv4) etherPacket.getPayload();
			UDP udp = (UDP) ip.getPayload();
			// get rip packet
			RIPv2 rip = (RIPv2) udp.getPayload();
			// Update the RIP table
			List<RIPv2Entry> entries = rip.getEntries();

			for (int i = 0; i < entries.size(); i++) {
				int nextHop = ip.getSourceAddress();
				int ipAddr = entries.get(i).getAddress();
				int mask = entries.get(i).getSubnetMask();
				int netAddr = ipAddr & mask;
				int metric = entries.get(i).getMetric() + 1;
				if (metric >= 17) {
					metric = 16;
				}

				synchronized (this.ripMap) {
					// Update
					if (ripMap.containsKey(netAddr)) {
						// if already has this data
						RipEntryData localEntry = ripMap.get(netAddr);
						localEntry.timestamp = System.currentTimeMillis();

						// Compare the cost
						if (metric < localEntry.metric) {
							// Update the lowest cost
							localEntry.metric = metric;

							// Update it
							this.routeTable.update(ipAddr, mask, nextHop, inIface);
						}

						if (metric >= 16) {
							RouteEntry bestMatch = this.routeTable.lookup(ipAddr);
							if (inIface.equals(bestMatch.getInterface())) {
								localEntry.metric = 16;
								if (null != bestMatch) {
									this.routeTable.remove(ipAddr, mask);
								}
							}
						}
					} else {
						// Insert
						ripMap.put(netAddr,
								new RipEntryData(ipAddr, mask, nextHop, metric, System.currentTimeMillis()));
						if (metric < 16) {
							// If there is no this data
							this.routeTable.insert(ipAddr, nextHop, mask, inIface);
						}
					}
				}
			}
		}
	}

	/**
	 * Send RIP packet
	 * 
	 * @param type        request or response
	 * @param etherPacket packet
	 * @param iface       interface
	 */
	private void sendRip(RIPType type, Ethernet etherPacket, Iface iface) {
		Ethernet e = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		// Set Ether header
		e.setSourceMACAddress(iface.getMacAddress().toBytes());
		e.setEtherType(Ethernet.TYPE_IPv4);

		// Set IP & UDP header
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(iface.getIpAddress());

		// Set Port
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);

		// decide type of RIP packet
		if (RIPType.RIP_REQ.equals(type)) {

			rip.setCommand(RIPv2.COMMAND_REQUEST);
			// Set fixed MAC: ff:ff:ff:ff:ff:ff
			e.setDestinationMACAddress(RIP_MAC_BROADCAST);
			// Set fixed IP: 224.0.0.9
			ip.setDestinationAddress(IPv4.toIPv4Address(RIP_IP_MULTICAST));
		} else if (RIPType.RIP_RESP.equals(type)) {
			// Response
			IPv4 ipPacket = (IPv4) etherPacket.getPayload();

			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			// Set source MAC Address
			e.setDestinationMACAddress(e.getSourceMACAddress());
			// Set source IP Address
			ip.setDestinationAddress(ipPacket.getSourceAddress());
		} else {
			// unsolicited RIP responses
			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			// Set fixed MAC: ff:ff:ff:ff:ff:ff
			e.setDestinationMACAddress(RIP_MAC_BROADCAST);
			// Set fixed IP: 224.0.0.9
			ip.setDestinationAddress(IPv4.toIPv4Address(RIP_IP_MULTICAST));
		}

		// Create the UDP payload
		List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>();
		synchronized (this.ripMap) {
			// Update RIP entry
			for (RipEntryData localEntry : ripMap.values()) {
				RIPv2Entry entry = new RIPv2Entry(localEntry.address, localEntry.mask, localEntry.metric);
				entries.add(entry);
			}
		}

		e.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);
		rip.setEntries(entries);
		sendPacket(e, iface);
	}
	/**
	 * ============RIP================================
	 */
}