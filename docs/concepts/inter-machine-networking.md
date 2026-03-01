# Inter-Machine Networking

## What Is a Cluster?

Imagine a computer lab at school. Every computer has its own screen,
keyboard, and memory — but they're all connected by cables to a central
switch. Any computer can send a message to any other.

That's a **cluster**: a group of computers (or in our case, PyOS kernels)
connected by a network so they can work together.

In the real world, clusters power everything from Google search to
weather forecasting. Instead of one giant computer, you connect many
smaller ones and split the work between them.

## The Network Bridge

The bridge is the **switch** in our computer lab analogy. It sits in
the middle and routes messages between kernels.

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│ Kernel 1 │◄───────►│  Bridge  │◄───────►│ Kernel 2 │
│ (web)    │         │  (switch)│         │ (db)     │
└──────────┘         └──────────┘         └──────────┘
                          ▲
                          │
                     ┌──────────┐
                     │ Kernel 3 │
                     │ (cache)  │
                     └──────────┘
```

Each kernel **registers** with the bridge and gets an ID. When one
kernel wants to talk to another, it creates a **packet** and hands it
to the bridge, which drops it in the destination kernel's inbox.

## Packets

A **packet** is like an envelope in the post. It has:

- **From**: which kernel sent it (source ID)
- **To**: which kernel should receive it (destination ID)
- **Contents**: the actual data (payload)
- **Type**: what kind of message it is

### Packet Types

| Type | What It's For |
|------|--------------|
| `DATA` | Regular messages between kernels |
| `PING` | "Are you there?" check |
| `PONG` | "Yes, I'm here!" reply |
| `DNS_QUERY` | "What's the IP for this hostname?" |
| `DNS_RESPONSE` | "Here's the IP address!" |

## What Can Clusters Do?

### Send Messages

Any kernel can send a message (bytes) to any other kernel in the cluster.
This is the foundation of all inter-machine communication.

### Ping

Ping is the simplest network test: "Can I reach you?" One kernel sends
a `PING` packet, and the other replies with `PONG`. If you get a pong
back, the other machine is alive and connected.

This is exactly what the `ping` command does on a real computer!

### Cross-Machine DNS

Each kernel has its own DNS resolver (phone book for hostnames).
With a cluster, you can ask *another* kernel to look up a hostname
for you. This is like calling a friend and asking them to look up a
phone number in their contacts.

## Try It in the Shell

```
PyOS> cluster create              # Initialize a cluster
Cluster created. This kernel is ID 1

PyOS> cluster add                 # Add a second kernel
Added kernel 2 to cluster

PyOS> cluster list                # See all kernels
ID    STATE      PENDING
1     running    0
2     running    0

PyOS> cluster ping 2              # Check if kernel 2 is reachable
Kernel 2: reachable

PyOS> cluster send 2 Hello!       # Send a message
Sent to kernel 2: Hello!

PyOS> cluster demo                # Run a full demonstration
=== Cluster Demo ===
Created kernel 1 and kernel 2
...
```

## How Real Networks Work

Our cluster is a simplified version of real networking, but the
concepts are the same:

| Our Concept | Real-World Equivalent |
|-------------|----------------------|
| `NetworkBridge` | Network switch / router |
| `Packet` | TCP/IP packet |
| `Cluster` | Server cluster (like a Kubernetes cluster) |
| `PING`/`PONG` | ICMP Echo Request/Reply |
| Cross-kernel DNS | DNS forwarding / recursive lookup |

The main difference is that our packets travel through Python objects
in memory, while real packets travel through copper cables, fibre optic
lines, or radio waves. But the *idea* — addressing, routing, and
message delivery — is identical.

## Why Does This Matter?

Almost nothing on the internet runs on a single computer anymore.
Every large website, app, or service is actually a **cluster** of
machines working together:

- **Google** uses millions of servers in clusters around the world
- **Netflix** streams video from clusters close to your location
- **Games** use clusters to handle millions of players at once

By understanding how machines communicate — packets, bridges, ping,
DNS — you're learning the building blocks of the internet itself!
