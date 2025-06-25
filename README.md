# Router – IPv4 Forwarding, ARP, and ICMP

### Author: Berescu Silvia-Maria 

## Overview

This project implements the dataplane of a router. The router processes incoming IPv4 packets, resolves ARP addresses, and generates ICMP responses when needed.

The router operates using a static routing table and handles packets received on any of its interfaces, either forwarding them toward their destination or responding with an error message.

## Features

This project includes implementations for:

- **IPv4 Routing Process**: IP header validation, checksum, TTL handling, forwarding logic, and ICMP message generation.
- **Efficient Longest Prefix Match (LPM)**: Uses binary search on a sorted routing table for optimal route selection.
- **ARP Protocol**: Dynamic ARP handling with caching and packet queuing during resolution.
- **ICMP Protocol**: Generation of Echo Reply, Time Exceeded, and Destination Unreachable messages.

## IPv4 Forwarding Logic

When a packet arrives:
1. IP Validation:
   - Check if it's an IPv4 packet.
   - If it’s an ICMP Echo Request addressed to the router, respond with an ICMP Echo Reply.

2. If the packet is not for the router:
   - Validate the IP checksum.
   - Check the TTL value:
     - If TTL is 0 or 1 -> send ICMP "Time Exceeded".
     - Otherwise → decrement TTL.
   - Use LPM to find the best route:
     - If no route is found -> send ICMP "Destination Unreachable".
   - If a route is found:
     - Check the ARP table for the next hop’s MAC address.
       - If known -> forward the packet.
       - If unknown -> send ARP Request and enqueue the packet.


## Longest Prefix Match

To efficiently match routes:
- The routing table is pre-sorted by prefix and mask length using quicksort.
- A binary search is used to find the most specific match for a destination IP address.
- This approach reduces route lookup time compared to linear scanning.

## ARP

If a packet is ready to be forwarded but the MAC address of the next hop is unknown:
- An "ARP Request" is sent.
- The packet is "queued" while waiting for the ARP Reply.

Once the ARP Reply is received:
- The ARP table is updated.
- All queued packets for that address are immediately forwarded.

## ICMP

Implemented ICMP features include:
- Echo Reply: Responds to ICMP Echo Requests addressed to the router.
- Time Exceeded: Sent when a packet’s TTL reaches 0 or 1.
- Destination Unreachable: Sent when no route to the destination is found.

