package csci476.lab3;

import org.jnetpcap.*;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.Date;

public class Main {

    public static void main(String[] args) {
        /***************************************************************************
         * First we setup error buffer and name for our file
         **************************************************************************/
        final StringBuilder errbuf = new StringBuilder(); // For any error msgs
        String file = "dump.pcap";
        try {
            file = args[1];
        } catch (Exception e) {

        }


        System.out.printf("Opening file for reading: %s%n", file);

        /***************************************************************************
         * Second we open up the selected file using openOffline call
         **************************************************************************/
        Pcap pcap = Pcap.openOffline(file, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        } else {
            System.out.println("File successfully opened.");
        }
        //Make somewhere for our data to be saved.
        final CaptureData captureData = new CaptureData();

        /***************************************************************************
         * Third we create a packet handler which will receive packets from the
         * libpcap loop.
         **************************************************************************/
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            //Called by jnetpcap for every packet received.
            public void nextPacket(PcapPacket packet, String user) {
                //Filter out TCP packets. We only want those. Anything else will not be part of a Syn/Syn-Ack attack.
                if(packet.hasHeader(Tcp.ID)) {
                    captureData.packetCount++;
                    //Check if this is a SYN packet (Not SYNACK).
                    //Find the actual byte that stores the flags because creating a TCP packet we don't need is expensive.
                    if(packet.getByte(47) == 0x02) {
                        captureData.synPacketCount++;
                        //Preallocate a TCP and IPv4 header
                        Tcp tcp = new Tcp();
                        Ip4 ip4 = new Ip4();
                        //Shove this packet's TCP and IPv4 information into tcp and ip4.
                        packet.getHeader(tcp);
                        packet.getHeader(ip4);
                        //Since this packet is a syn, and we obviously haven't received a response,
                        // lets add it to the stack.
                        //NOTE: The TCP header does not store IP address information, so it is lost when stored.
                        // We can associate 2 TCP packet headers using their Sequence numbers.
                        captureData.synPacketsWithoutAck.push(tcp);
                        //Bookkeeping: We need to keep track of the count for each IP in our Hash Map.

                        //If the item already exists, use replace to add 1 to the value.
                        if(captureData.ipsWithoutResponses.containsKey(FormatUtils.ip(ip4.source()))) {
                            captureData.ipsWithoutResponses.get(FormatUtils.ip(ip4.source())).value++;
                        } else {
                            captureData.ipsWithoutResponses.put(FormatUtils.ip(ip4.source()), new CaptureData.MutableInt());
                        }
                    }
                    //Check if this is a SYN-ACK packet.
                    else if(packet.getByte(47) == 0x12) {
                        captureData.synackPacketCount++;
                        //Preallocate a TCP header
                        Tcp tcp = new Tcp();
                        //Shove this packet's TCP information into tcp.
                        packet.getHeader(tcp);
                        //This is a SYNACK for some SYN on the stack. Lets find it, starting
                        // from the top of the stack.

                    }
                }

            }
        };

        /***************************************************************************
         * Fourth we enter the loop and tell it to capture 10 packets. The loop
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
         * is needed by JScanner. The scanner scans the packet buffer and decodes
         * the headers. The mapping is done automatically, although a variation on
         * the loop method exists that allows the programmer to sepecify exactly
         * which protocol ID to use as the data link type for this pcap interface.
         **************************************************************************/
        try {
            //Arguments, Read all the packets, the packet handle, extra string you pass in with no useful information.
            System.out.println("Searching for TCP SYN and SYN-ACK packets. This may take a very long time.");
            pcap.loop(-1, jpacketHandler, "capture");
        } finally {
            /***************************************************************************
             * Last thing to do is close the pcap handle
             **************************************************************************/
            pcap.close();
        }
        //Everything we need will be saved in the captureData we made. This is the only way I could figure out
        // how to save data from the subclass.
        System.out.println("Number of TCP packets read: " + captureData.packetCount);
        System.out.println("Number of SYN packets read: " + captureData.synPacketCount);
        System.out.println("Number of SYN-ACK packets read: " + captureData.synackPacketCount);
    }
}
