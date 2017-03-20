package csci476.lab3;

import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Stack;

/**
 * Created by cetho on 3/19/2017.
 */
public class CaptureData {
    public int packetCount = 0;
    public int synPacketCount = 0;
    public int synackPacketCount = 0;

    //Use a stack, because responses are likely to be for the most recently received SYN.
    //Stores all SYN packets we've seen so far without any sort of response.
    //Shrinks and grows as more SYNs and responses are found.
    public Stack<Tcp> synPacketsWithoutAck = new Stack<Tcp>();
    //Store a count of how many times a host has created a SYN without a response.
    //Key: String: IP Address
    //Value: integer count of SYNs without ACKs.
    public HashMap<String, MutableInt> ipsWithoutResponses = new HashMap<String, MutableInt>();
    //Store a count of how many times a host has created a SYN and recieved an ACK.
    //Key: String: IP Address
    //Value: integer count of SYNACK pairs.
    public HashMap<String, MutableInt> ipsWithResponses = new HashMap<String, MutableInt>();

    public static class MutableInt {
        public int value = 1;
    }
}
