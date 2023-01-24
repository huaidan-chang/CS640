import enum
import logging
import llp
import queue
import struct
import threading


class SWPType(enum.IntEnum):
    DATA = ord('D')
    ACK = ord('A')


class SWPPacket:
    _PACK_FORMAT = '!BI'
    _HEADER_SIZE = struct.calcsize(_PACK_FORMAT)
    MAX_DATA_SIZE = 1400  # Leaves plenty of space for IP + UDP + SWP header

    def __init__(self, type, seq_num, data=b''):
        self._type = type
        self._seq_num = seq_num
        self._data = data

    @property
    def type(self):
        return self._type

    @property
    def seq_num(self):
        return self._seq_num

    @property
    def data(self):
        return self._data

    def to_bytes(self):
        header = struct.pack(SWPPacket._PACK_FORMAT, self._type.value,
                             self._seq_num)
        return header + self._data

    @classmethod
    def from_bytes(cls, raw):
        header = struct.unpack(SWPPacket._PACK_FORMAT,
                               raw[:SWPPacket._HEADER_SIZE])
        type = SWPType(header[0])
        seq_num = header[1]
        data = raw[SWPPacket._HEADER_SIZE:]
        return SWPPacket(type, seq_num, data)

    def __str__(self):
        return "%s %d %s" % (self._type.name, self._seq_num, repr(self._data))


class SWPSender:
    _SEND_WINDOW_SIZE = 5
    _TIMEOUT = 1

    def __init__(self, remote_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(remote_address=remote_address,
                                             loss_probability=loss_probability)

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()

        # TODO: Add additional state variables
        self.send_window_sema = threading.Semaphore(
            value=SWPSender._SEND_WINDOW_SIZE)
        self.buffer = {}
        self.buffer_sema = threading.Semaphore()
        self.last_sent = -1
        self.last_ack = -1
        self.seq_no = 0
        self.seq_no_sema = threading.Semaphore()
        self.timers = {}

    def send(self, data):
        for i in range(0, len(data), SWPPacket.MAX_DATA_SIZE):
            self._send(data[i:i+SWPPacket.MAX_DATA_SIZE])

    def _send(self, data):
        # TODO
        # Wait for a free space in the send window
        self.send_window_sema.acquire()

        with self.seq_no_sema:
            # Construct packet
            packet = SWPPacket(type=SWPType.DATA,
                            seq_num=self.seq_no, data=data)

            with self.buffer_sema:
                # Add the chunk of data to a buffer
                self.buffer[self.seq_no] = data

            # transmit the packet across the network
            logging.debug("Sent: %s" % packet)
            self._llp_endpoint.send(raw_bytes=packet.to_bytes())

            # set timer for one second
            timer = threading.Timer(interval=SWPSender._TIMEOUT,
                                    function=SWPSender._retransmit, args=[self, self.seq_no])
            self.timers[self.seq_no] = timer
            timer.start()

            # increment sequence number
            self.last_sent = self.seq_no
            self.seq_no += 1

        return

    def _retransmit(self, seq_num):
        # TODO

        with self.seq_no_sema:
            # Construct packet
            data = None
            with self.buffer_sema:
                data = self.buffer[seq_num]
            
            if data == None:
                return
            
            packet = SWPPacket(type=SWPType.DATA,
                            seq_num=seq_num, data=data)
            
            # transmit the packet across the network
            logging.debug("Sent: %s" % packet)
            self._llp_endpoint.send(raw_bytes=packet.to_bytes())

            # set timer for one second
            timer = threading.Timer(interval=SWPSender._TIMEOUT,
                                    function=SWPSender._retransmit, args=[self, seq_num])
            self.timers[seq_num] = timer
            timer.start()
        return

    def _recv(self):
        while True:
            # Receive SWP packet
            raw = self._llp_endpoint.recv()
            if raw is None:
                continue
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)

            # TODO
            # SWP sender should only receive SWP ACK packets
            if packet.type != SWPType.ACK:
                continue
            
            with self.seq_no_sema:
                if packet.seq_num > self.last_ack:
                    for i in range(self.last_ack + 1, packet.seq_num + 1):
                        # 1. Cancel the retransmission timer
                        timer = self.timers[i]
                        if (timer is not None):
                            timer.cancel()
                            del self.timers[i]
                        # 2. Discard that chunk of data.
                        del self.buffer[i]

                    # 3. Signal that there is now a free space in the send window
                    self.send_window_sema.release()
                    self.last_ack = packet.seq_num 
        return

class SWPReceiver:
    _RECV_WINDOW_SIZE = 5

    def __init__(self, local_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(local_address=local_address,
                                             loss_probability=loss_probability)

        # Received data waiting for application to consume
        self._ready_data = queue.Queue()

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()

        # TODO: Add additional state variables
        self.buffer = {}
        self.highest_seq_num = 0

        # Largest Acceptable Frame
        self.LAF = 4

        # Last Frame Received
        self.LFR = -1


    def recv(self):
        return self._ready_data.get()

    def _recv(self):
        while True:
            # Receive data packet
            raw = self._llp_endpoint.recv()
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)

            # TODO
            if packet.type != SWPType.DATA: 
                continue

            if packet.seq_num > self.LAF:
                continue

            # the chunk of data was already acknowledged and retransmit an SWP ACK
            # containing the highest acknowledged sequence number.
            if (packet.seq_num <= self.LFR):
                ack = SWPPacket(SWPType.ACK, self.highest_seq_num)
                self._llp_endpoint.send(ack.to_bytes())
                continue

            # Add the chunk of data to a buffer
            self.buffer[packet.seq_num] = packet

            # Traverse the buffer
            i = self.LFR + 1
            while i in self.buffer:
                if i > self.LAF:
                    break
                self.highest_seq_num = i
                self._ready_data.put(self.buffer[i].data)
                del self.buffer[i]
                i += 1
            
            ack = SWPPacket(SWPType.ACK, self.highest_seq_num)
            logging.debug("Sent: %s" % ack)
            self._llp_endpoint.send(ack.to_bytes())

            self.LFR = self.highest_seq_num
            self.LAF = self.LFR + self._RECV_WINDOW_SIZE

        return
