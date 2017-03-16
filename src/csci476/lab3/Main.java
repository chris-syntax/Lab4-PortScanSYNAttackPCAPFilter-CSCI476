package csci476.lab3;

import org.jnetpcap.*;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.util.Date;

public class Main {

    public static void main(String[] args) {
        /***************************************************************************
         * First we setup error buffer and name for our file
         **************************************************************************/
        final StringBuilder errbuf = new StringBuilder(); // For any error msgs
        final String file = "dump.pcap";

        System.out.printf("Opening file for reading: %s%n", file);

        /***************************************************************************
         * Second we open up the selected file using openOffline call
         **************************************************************************/
        Pcap pcap = Pcap.openOffline(file, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        /***************************************************************************
         * Third we create a packet handler which will receive packets from the
         * libpcap loop.
         **************************************************************************/
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {

                System.out.printf("Received at %s caplen=%-4d len=%-4d %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(), // Length actually captured
                        packet.getCaptureHeader().wirelen(), // Original length
                        user // User supplied object
                );
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
            pcap.loop(10, jpacketHandler, "jNetPcap rocks!");
        } finally {
            /***************************************************************************
             * Last thing to do is close the pcap handle
             **************************************************************************/
            pcap.close();
        }
    }
}
