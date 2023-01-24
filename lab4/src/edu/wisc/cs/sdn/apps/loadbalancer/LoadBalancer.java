package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.l3routing.L3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener, IOFMessageListener {
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();

	private static final byte TCP_FLAG_SYN = 0x02;

	private static final short IDLE_TIMEOUT = 20;

	// Interface to the logging system
	private static Logger log = LoggerFactory.getLogger(MODULE_NAME);

	// Interface to Floodlight core for interacting with connected switches
	private IFloodlightProviderService floodlightProv;

	// Interface to device manager service
	private IDeviceService deviceProv;

	// Switch table in which rules should be installed
	private byte table;

	// Set of virtual IPs and the load balancer instances they correspond with
	private Map<Integer, LoadBalancerInstance> instances;

	/**
	 * Loads dependencies and initializes data structures.
	 */
	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		log.info(String.format("Initializing %s...", MODULE_NAME));

		// Obtain table number from config
		Map<String, String> config = context.getConfigParams(this);
		this.table = Byte.parseByte(config.get("table"));

		// Create instances from config
		this.instances = new HashMap<Integer, LoadBalancerInstance>();
		String[] instanceConfigs = config.get("instances").split(";");
		for (String instanceConfig : instanceConfigs) {
			String[] configItems = instanceConfig.split(" ");
			if (configItems.length != 3) {
				log.error("Ignoring bad instance config: " + instanceConfig);
				continue;
			}
			LoadBalancerInstance instance = new LoadBalancerInstance(configItems[0], configItems[1],
					configItems[2].split(","));
			this.instances.put(instance.getVirtualIP(), instance);
			log.info("Added load balancer instance: " + instance);
		}

		this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
		this.deviceProv = context.getServiceImpl(IDeviceService.class);

		/*********************************************************************/
		/* TODO: Initialize other class variables, if necessary */

		/*********************************************************************/
	}

	/**
	 * Subscribes to events and performs other startup tasks.
	 */
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);

		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary */

		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch joins the network.
	 * 
	 * @param DPID for the switch
	 */
	@Override
	public void switchAdded(long switchId) {
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));

		/*********************************************************************/
		/* TODO: Install rules to send: */
		/* (1) packets from new connections to each virtual load */
		/* balancer IP to the controller */
		/* (2) ARP packets to the controller, and */
		/* (3) all other packets to the next rule table in the switch */

		// (1) packets from new connections to each virtual load
		// balancer IP to the controller
		for (Integer virtualIP : instances.keySet()) {
			// creating a new OFMatch object
			OFMatch match = new OFMatch();
			// you must set the Ethernet Type before you set the destination IP
			match.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
			// set the destination IP
			match.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
			match.setNetworkDestination(virtualIP);

			// the rule should include an OFInstructionApplyActions
			// whose set of actions consists of a single OFActionOutput
			// with OFPort.OFPP_CONTROLLER as the port number
			OFAction actOut = new OFActionOutput(OFPort.OFPP_CONTROLLER);
			OFInstruction instrAct = new OFInstructionApplyActions(Arrays.asList(actOut));
			// Installs a IP rule in a switch's flow table
			SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY), match,
					Arrays.asList(instrAct));
		}

		// (2) ARP packets to the controller
		OFMatch arpMatch = new OFMatch();
		arpMatch.setDataLayerType(OFMatch.ETH_TYPE_ARP);
		OFAction arpActOut = new OFActionOutput(OFPort.OFPP_CONTROLLER);
		OFInstruction arpInstrAct = new OFInstructionApplyActions(Arrays.asList(arpActOut));
		// Installs a ARP rule in a switch's flow table
		SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY), arpMatch,
				Arrays.asList(arpInstrAct));

		// (3) all other packets to the next rule table in the switch
		// When a packet should be processed by the SDN switch based on the rules
		// installed by your layer-3 routing application, a rule should include an
		// OFInstructionGotoTable whose table number is the value specified in the table
		// class variable in the L3Routing class
		OFMatch allMatch = new OFMatch();
		OFInstruction instrGotoTable = new OFInstructionGotoTable(L3Routing.table);
		SwitchCommands.installRule(sw, table, (short) (SwitchCommands.DEFAULT_PRIORITY), allMatch,
				Arrays.asList(instrGotoTable));
		/*********************************************************************/
	}

	/**
	 * Handle incoming packets sent from switches.
	 * 
	 * @param sw   switch on which the packet was received
	 * @param msg  message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN) {
			return Command.CONTINUE;
		}
		OFPacketIn pktIn = (OFPacketIn) msg;

		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);

		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/* SYNs sent to a virtual IP, select a host and install */
		/* connection-specific rules to rewrite IP and MAC addresses; */
		/* ignore all other packets */

		// Send an ARP reply for ARP requests for virtual IPs
		if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
			ARP arpReq = (ARP) ethPkt.getPayload();
			if (arpReq.getOpCode() == ARP.OP_REQUEST) {
				int virtualIP = IPv4.toIPv4Address(arpReq.getTargetProtocolAddress());
				// Construct and send an ARP reply packet when a client requests the MAC address
				// associated with a virtual IP
				if (this.instances.containsKey(virtualIP)) {
					LoadBalancerInstance lb = instances.get(virtualIP);
					byte[] virtualMac = lb.getVirtualMAC();

					Ethernet ether = new Ethernet();
					ether.setEtherType(Ethernet.TYPE_ARP);
					ether.setSourceMACAddress(virtualMac);
					ether.setDestinationMACAddress(ethPkt.getSourceMACAddress());

					ARP arp = new ARP();
					arp.setHardwareType(arpReq.getHardwareType());
					arp.setProtocolType(arpReq.getProtocolType());
					arp.setHardwareAddressLength(arpReq.getHardwareAddressLength());
					arp.setProtocolAddressLength(arpReq.getProtocolAddressLength());
					arp.setSenderHardwareAddress(virtualMac);
					arp.setSenderProtocolAddress(virtualIP);

					arp.setOpCode(ARP.OP_REPLY);
					// set to the sender hardware address from the original packet
					arp.setTargetHardwareAddress(arpReq.getSenderHardwareAddress());
					// set to the sender protocol address from the original packet
					arp.setTargetProtocolAddress(arpReq.getSenderProtocolAddress());
					ether.setPayload(arp);
					SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), ether);
				}
			}
		} else if (ethPkt.getEtherType() == Ethernet.TYPE_IPv4) {
			IPv4 ip = (IPv4) ethPkt.getPayload();
			if (ip.getProtocol() == IPv4.PROTOCOL_TCP) {
				TCP tcp = (TCP) ip.getPayload();
				// When clients initiate TCP connections with a specific virtual IP, SDN
				// switches will send the TCP SYN packet to the SDN controller.

				// for TCP SYNs sent to a virtual IP, select a host and install
				// connection-specific rules to rewrite IP and MAC addresses
				if (tcp.getFlags() == TCP_FLAG_SYN) {
					int virtualIP = ip.getDestinationAddress();
					LoadBalancerInstance lb = instances.get(virtualIP);
					// the load balancer selects one of the specified hosts in round-robin order
					int nextIP = lb.getNextHostIP();

					// install connection-specific rules to rewrite IP and MAC addresses

					// Rule: clients to the load balancer
					// For all packets sent from clients to the load balancer, the load balancer
					// rewrites the destination IP and MAC addresses to the IP and MAC addresses of
					// the selected host.
					OFMatch inMatch = new OFMatch();
					inMatch.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
					inMatch.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
					inMatch.setNetworkSource(ip.getSourceAddress());
					inMatch.setNetworkDestination(virtualIP);
					// TCP source port
					inMatch.setTransportSource(tcp.getSourcePort());
					// TCP destination port
					inMatch.setTransportDestination(tcp.getDestinationPort());

					// OFInstructionApplyActions whose set of actions consists of
					// An OFActionSetField with a field type of OFOXMFieldType.ETH_DST and the
					// desired MAC address as the value
					// An OFActionSetField with a field type of OFOXMFieldType.IPV4_DST and the
					// desired IP address as the value
					OFAction ethDstField = new OFActionSetField(OFOXMFieldType.ETH_DST,
							getHostMACAddress(nextIP));
					OFAction ipDstField = new OFActionSetField(OFOXMFieldType.IPV4_DST, nextIP);

					OFInstruction instrAct = new OFInstructionApplyActions(
							Arrays.asList(ipDstField, ethDstField));
					OFInstruction instrGotoTable = new OFInstructionGotoTable(L3Routing.table);
					// connection-specific rules should have an idle timeout of 20 seconds
					SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 1), inMatch,
							Arrays.asList(instrAct, instrGotoTable), SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);

					// Rule: servers to clients
					// For all packets sent from servers to clients,
					// the load balancer rewrites the source IP and MAC addresses to the IP and MAC
					// addresses of the load balancer.
					OFMatch outMatch = new OFMatch();
					outMatch.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
					outMatch.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
					outMatch.setNetworkSource(nextIP);
					outMatch.setNetworkDestination(ip.getSourceAddress());
					// TCP source port
					outMatch.setTransportSource(OFMatch.IP_PROTO_TCP, tcp.getDestinationPort());
					// TCP destination port
					outMatch.setTransportDestination(OFMatch.IP_PROTO_TCP, tcp.getSourcePort());

					OFAction ethSrcField = new OFActionSetField(OFOXMFieldType.ETH_SRC,
							lb.getVirtualMAC());
					OFAction ipSrcField = new OFActionSetField(OFOXMFieldType.IPV4_SRC, virtualIP);

					OFInstruction instrOutAct = new OFInstructionApplyActions(
							Arrays.asList(ipSrcField, ethSrcField));
					instrGotoTable = new OFInstructionGotoTable(L3Routing.table);
					// connection-specific rules should have an idle timeout of 20 seconds
					SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 1), outMatch,
							Arrays.asList(instrOutAct, instrGotoTable), SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);
				}
			}
		}

		/*********************************************************************/

		// We don't care about other packets
		return Command.CONTINUE;
	}

	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * 
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress) {
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(null, null, hostIPAddress, null, null);
		if (!iterator.hasNext()) {
			return null;
		}
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * 
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) {
		/* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * 
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) {
		/* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is added or
	 * removed.
	 * 
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port, PortChangeType type) {
		/* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * 
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) {
		/* Nothing we need to do */ }

	/**
	 * Tell the module system which services we provide.
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	/**
	 * Tell the module system which services we implement.
	 */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	/**
	 * Tell the module system which modules we depend on.
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> floodlightService = new ArrayList<Class<? extends IFloodlightService>>();
		floodlightService.add(IFloodlightProviderService.class);
		floodlightService.add(IDeviceService.class);
		return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * 
	 * @return name for this module
	 */
	@Override
	public String getName() {
		return MODULE_NAME;
	}

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (OFType.PACKET_IN == type
				&& (name.equals(ArpServer.MODULE_NAME) || name.equals(DeviceManagerImpl.MODULE_NAME)));
	}

	/**
	 * Check if events must be passed to another module after this module has been
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}
}
