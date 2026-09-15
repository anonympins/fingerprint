package com.anonympins.fingerprint;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class BlockList {
    private final List<Subnet> subnets = new ArrayList<>();
    private final List<InetAddress> addresses = new ArrayList<>();

    public void addAddress(String ip) {
        try {
            addresses.add(InetAddress.getByName(ip));
        } catch (UnknownHostException e) {
            // ignore
        }
    }

    public void addSubnet(String ip, int prefix) {
        try {
            subnets.add(new Subnet(InetAddress.getByName(ip), prefix));
        } catch (UnknownHostException e) {
            // ignore
        }
    }

    public void add(String entry) {
        if (entry.contains("/")) {
            String[] parts = entry.split("/");
            addSubnet(parts[0], Integer.parseInt(parts[1]));
        } else {
            addAddress(entry);
        }
    }

    public boolean check(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            for (InetAddress address : addresses) {
                if (address.equals(addr)) {
                    return true;
                }
            }
            for (Subnet subnet : subnets) {
                if (subnet.contains(addr)) {
                    return true;
                }
            }
        } catch (UnknownHostException e) {
            // ignore
        }
        return false;
    }

    private static class Subnet {
        private final byte[] network;
        private final int prefix;

        public Subnet(InetAddress address, int prefix) {
            this.network = address.getAddress();
            this.prefix = prefix;
        }

        public boolean contains(InetAddress address) {
            byte[] addr = address.getAddress();
            if (addr.length != network.length) {
                return false;
            }
            int bytesToCompare = prefix / 8;
            for (int i = 0; i < bytesToCompare; i++) {
                if (addr[i] != network[i]) {
                    return false;
                }
            }
            return true;
        }
    }
}