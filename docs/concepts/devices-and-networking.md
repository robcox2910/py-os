# Devices and Networking: How the OS Talks to Hardware and the World

Your computer is surrounded by stuff -- a screen, a keyboard, a printer, a
Wi-Fi card. And your programs constantly want to talk to these things: "print
this document," "show this pixel," "send this message across the internet."

But every device is different on the inside. A printer doesn't work anything
like a keyboard, and neither of them works like a Wi-Fi card. Somebody has to
translate between your programs and all this varied hardware.

That somebody is the OS.

In PyOS, this area is split across four files. Let's walk through each one.

---

## 1. Devices (`io/devices.py`)

### The School Supplies Analogy

Imagine a school that provides tools for students: printers, projectors,
whiteboards. They all work completely differently on the inside. A printer has
ink cartridges and rollers. A projector has a lamp and a lens. A whiteboard is
just... a board.

But the school doesn't make you learn how each tool works internally. Instead,
it gives you the same simple instructions for every tool: "read from it" or
"write to it." Want the projector to show something? Write to it. Want to see
what's on the whiteboard? Read from it. Same instructions, every time.

In computing, this idea is called a **uniform interface** (or a **protocol**).
Every device supports the same basic operations -- `name`, `status`, `read()`,
and `write()` -- even though the devices themselves do wildly different things.
Your program doesn't need to know *how* a printer works to use it. It just
calls `write()` and the device handles the rest.

In PyOS, the `Device` protocol defines these four operations. Any Python class
that has a `name`, a `status`, a `read()` method, and a `write()` method counts
as a valid device. This is Python's **duck typing** at work -- if it walks like
a device and quacks like a device, it *is* a device.

### Three Built-In Devices

#### NullDevice (`/dev/null`) -- The Trash Can

Think of a trash can. You can throw anything in it -- paper, wrappers, old
homework. It all disappears. If you try to pull something *out* of the trash
can, you get nothing.

That's exactly what `NullDevice` does. You can write any data to it, and the
data is silently discarded. If you try to read from it, you get back empty
bytes. It's always ready and it never fails.

Why would you want a device that throws everything away? It's surprisingly
useful. Sometimes a program produces output you don't care about -- log
messages, status updates, debug information. Instead of building a special
"ignore this output" feature into every program, you just point the output at
`/dev/null` and it vanishes. Simple.

#### ConsoleDevice -- The Whiteboard

Think of a classroom whiteboard. A teacher writes a message on it, and later
a student reads it. If the teacher writes three messages, the student reads
them in the same order they were written. First message in, first message out.

This ordering is called **FIFO** -- "first in, first out." It's the same idea
as a queue at a lunch counter. Whoever gets in line first gets served first.

The `ConsoleDevice` works the same way. You write data to it, and the data
goes into a buffer (a waiting area). When someone reads from it, they get the
oldest piece of data first. In a real OS, the console device would be backed
by actual screen hardware, but in PyOS we simulate it with a Python `deque` (a
double-ended queue).

#### RandomDevice (`/dev/random`) -- The Magic 8-Ball

You know those Magic 8-Balls where you shake it and get a random answer every
time? That's `/dev/random`. Every time you read from it, you get back random
bytes -- a different answer each time.

Unlike the other devices, this one is **read-only**. You can't write to it. If
you try, it raises an `OSError`. This makes sense -- you don't tell a random
number generator what to produce. You just ask it for bytes and it gives you
whatever it comes up with. Under the hood, PyOS uses Python's `os.urandom()`
to generate cryptographically random bytes.

### The Device Manager

In a real OS, there's a directory called `/dev` that lists all the devices
available on the system. PyOS has something similar: the `DeviceManager`. It's
a registry -- a lookup table -- where devices are registered by name. You can
add a new device, look one up by name, or list all the devices that are
currently registered.

If you try to register two devices with the same name, the manager raises a
`ValueError`. Just like you can't have two files with the same name in the same
folder.

---

## 2. IPC -- Inter-Process Communication (`io/ipc.py`)

[Processes](processes.md) are isolated by design -- each one lives in its own
little world with its own [memory](memory.md), and it can't peek at what other
processes are doing. That's great for safety, but it creates a problem: what if
two processes *need* to share information?

That's where **IPC** comes in. IPC stands for "inter-process communication,"
which is a fancy way of saying "how processes talk to each other."

PyOS provides three IPC mechanisms. Think of them as three different ways
students in a school can pass information without talking out loud.

### Pipes -- The Tin-Can Telephone

Remember those toy telephones made from two tin cans connected by a string? One
kid talks into one can, and the other kid listens at the other end. The sound
travels in one direction through the string.

A **pipe** works just like that. One process writes bytes into one end of the
pipe, and another process reads bytes out of the other end. The data flows in
one direction, and it comes out in the same order it went in (FIFO again).

Here's what you can do with a pipe:

- **Write** -- push bytes into the pipe. If the pipe has been closed, you get a
  `BrokenPipeError` (like trying to talk into a tin can when someone has cut the
  string).
- **Read** -- pull the next chunk of bytes out. If the pipe is empty, you get
  `None`.
- **Close** -- shut the pipe for writing. Data already inside can still be read
  (drained), but no new data goes in.

Pipes are great for simple, streaming communication. If you've ever used the
`|` symbol in a command line (like `ls | grep ".py"`), you've used a pipe. The
output of one command flows directly into the input of the next.

### Message Queues -- The Mailbox

Now imagine a mailbox mounted on the wall. Anyone can walk up and drop a message
in. Anyone else can open the mailbox and take the next message out. Messages
come out in the order they were put in (FIFO, once again).

A **message queue** is exactly that. But it has two advantages over a pipe:

1. **Messages stay whole.** With a pipe, you're sending raw bytes -- just a
   stream of data with no boundaries. With a message queue, each message is a
   separate, complete unit. You put in "meeting at 3pm" and you get back
   "meeting at 3pm" -- not "meet" and then "ing at 3pm."

2. **Type safety.** In PyOS, message queues are **generic** -- you can create
   a `MessageQueue[str]` that only accepts and returns strings, or a
   `MessageQueue[int]` that only works with integers. Python checks the types
   for you so you don't accidentally put the wrong kind of data into the queue.

Message queues are also **named**. You give the queue a name when you create it
(like "print_jobs" or "notifications"), and any process that knows the name can
find it and send or receive messages. This is great for many-to-many
communication -- multiple processes can all send to the same queue, and multiple
processes can all read from it.

### Shared Memory -- The Shared Whiteboard

Pipes and message queues are great, but they both involve **copying** data. The
sender writes data into the pipe or queue, and the receiver reads its own copy
out. For small messages that's fine, but what if two processes need to share a
huge chunk of data -- like a big spreadsheet or a video frame? Copying all that
data back and forth would be slow.

**Shared memory** solves this by giving multiple processes access to the *same*
chunk of memory. No copying at all.

Think of a whiteboard in the school hallway. Any student can walk up and write
on it, and every other student can see what's there instantly. Nobody has to
copy anything -- they're all looking at the same board. That's shared memory.

Here's how it works in PyOS:

1. **Create** -- a process asks the kernel to set up a named whiteboard (a
   shared memory segment) of a certain size. The kernel allocates physical
   memory frames to back it, just like it does for [virtual memory](memory.md).
   The name is like a label on the whiteboard ("project-data" or "scoreboard").

2. **Attach** -- any process that knows the name can attach to the segment.
   The kernel maps the segment's frames into that process's virtual address
   space so it can read and write directly. Multiple processes can attach at
   the same time.

3. **Read / Write** -- attached processes read and write bytes directly.
   Because everyone is looking at the same underlying memory, a write by one
   process is instantly visible to all others. Zero copying.

4. **Detach** -- when a process is done, it detaches. The kernel unmaps the
   frames from that process's address space, but the whiteboard stays up for
   anyone else still using it.

5. **Destroy** -- when nobody needs the whiteboard anymore, any process can
   ask the kernel to destroy it. If processes are still attached, the kernel
   marks it "for deletion" and waits. Once the last process detaches, the
   memory is freed.

#### The Synchronization Problem

Here's the catch. Shared memory is the fastest IPC mechanism -- but it's also
the most dangerous if you're not careful.

Imagine two students try to write on the whiteboard at the exact same time.
One writes "Meeting at 3" and the other writes "Pizza party." You might end
up with "MePizzting party at 3" -- a garbled mess. This is called a **race
condition**.

To prevent this, processes need a way to take turns. That's where
[synchronization primitives](synchronization.md) come in -- mutexes,
semaphores, and reader-writer locks can all coordinate access to shared
memory. Think of it like a "WRITING -- DO NOT ERASE" sign that a student
puts on the whiteboard while they're using it.

Real operating systems face this exact same challenge. Shared memory gives you
speed, but you have to be disciplined about synchronization. That's the
trade-off.

### Pipes vs. Message Queues vs. Shared Memory -- When to Use Which?

- Use a **pipe** when you have a simple producer-consumer setup: one process
  generates a stream of bytes, and another consumes it. Think "command output."
- Use a **message queue** when you need structured, discrete messages and
  possibly many senders or receivers. Think "task assignments" or "event
  notifications."
- Use **shared memory** when you need fast, random-access, bidirectional data
  sharing between processes. Think "shared spreadsheet" or "game state." Just
  remember to add synchronization.

---

## 3. Disk Scheduling (`io/disk.py`)

### The Elevator Analogy

Picture a really tall building with 200 floors. There's one elevator, and it
moves up and down to pick people up. Lots of people are pressing buttons on
different floors at the same time, and the elevator has to decide: which floor
do I go to next?

A hard drive works the same way. It has a **read head** (the elevator) that
moves across the surface of the disk to different positions called
**cylinders** (the floors). When several [processes](processes.md) want to read
or write data at the same time, the OS has to decide which order to visit those
positions. The time it takes the head to move from one position to another is
called **seek time**, and it's the slowest part of the whole operation. So
choosing a good order really matters.

PyOS implements four strategies, and they're all named after how the elevator
could behave.

### FCFS -- First Come, First Served

The simplest rule: visit floors in the order people pressed the button.

If someone on floor 98 pressed first, then floor 3, then floor 175, then floor
14, the elevator goes: 98, 3, 175, 14. It zigzags all over the building like
crazy.

This is perfectly fair -- nobody gets skipped. But the total distance the
elevator travels is huge because it never plans ahead. It just blindly follows
the order of the requests.

### SSTF -- Shortest Seek Time First

A greedier rule: always go to the *nearest* floor.

If the elevator is on floor 53 and the requests are at floors 98, 3, 175, and
14, it would go to 14 first (closest), then 3, then 98, then 175. Much less
zigzagging.

The problem? **Starvation.** Imagine the elevator is near floor 50, and people
keep pressing buttons near floor 50. Someone on floor 199 might wait *forever*
because there's always a closer request. It's fast in the short term but
potentially unfair.

### SCAN -- The Elevator Algorithm

This is actually how most real elevators work. The elevator picks a direction --
say, up -- and goes all the way up, picking up everyone along the way. When it
reaches the top, it reverses and goes all the way down, picking up everyone on
the way down.

Nobody waits more than two full trips (one up, one down). There's no
starvation -- everyone gets served eventually. The total distance traveled is
much better than FCFS because the elevator moves in a predictable sweep
instead of zigzagging randomly.

### C-SCAN -- Circular SCAN

C-SCAN is a variation of SCAN with one twist: the elevator only picks people up
in one direction. It goes all the way up, and when it hits the top, instead of
turning around, it jumps straight back to the bottom and goes up again. It
never services requests on the way down.

Why? With regular SCAN, floors near the middle of the building get visited
twice per cycle (once going up, once going down), while floors at the very top
or bottom only get visited once. C-SCAN fixes this unfairness by treating the
disk like a circle -- after the top, wrap around to the bottom. Everyone gets
roughly the same wait time.

### The Classic Textbook Example

OS textbooks love this example. Imagine 8 requests at positions 98, 183, 37,
122, 14, 124, 65, and 67, with the read head starting at position 53.

Using FCFS, the head visits them in arrival order and travels a total of **640
positions** -- zigzagging wildly back and forth. Using SCAN, the head sweeps in
one direction and then the other, covering far fewer positions overall. The
difference is dramatic, and it shows why disk scheduling matters.

### The DiskScheduler

PyOS wraps these policies in a `DiskScheduler` object. You give it a policy
(FCFS, SSTF, SCAN, or C-SCAN) and a starting head position, then add requests
to its queue. When you call `run()`, it uses the policy to determine the
service order, moves the head to the last position serviced, and clears the
queue. You can even swap policies at runtime -- this is an example of the
**Strategy pattern**, where you can change an object's behaviour by plugging
in a different strategy.

---

## 4. Networking (`io/networking.py`)

### The Phone Call Analogy

Think of sockets as phone calls between two buildings.

Building A is a pizza shop (the **server**). Building B is a hungry customer
(the **client**). Here's how the call works:

**The server (pizza shop) side:**

1. **Get a phone** -- create a socket. At this point you have a phone, but it
   doesn't have a number yet.
2. **Assign a phone number** -- bind the socket to an address and a port. The
   address is like the area code ("localhost"), and the port is the specific
   phone number (like 8080). Now people can reach you.
3. **Start answering calls** -- call `listen()`. You're sitting by the phone,
   ready for customers to call.
4. **Pick up when someone calls** -- call `accept()`. This gives you a direct
   line to that specific customer.
5. **Talk** -- use `send()` and `recv()` to exchange data back and forth.

**The client (customer) side:**

1. **Get a phone** -- create a socket.
2. **Dial the pizza shop's number** -- call `connect()` with the server's
   address and port. If nobody's listening at that number, you get a
   `ConnectionError` ("connection refused" -- nobody picked up).
3. **Talk** -- use `send()` and `recv()` to place your order and hear back.

### Socket States

A socket goes through a series of states during its life, like chapters in a
phone call:

- **CREATED** -- you have a phone, but no number assigned. You can't call
  anyone yet and nobody can call you.
- **BOUND** -- you've been assigned a phone number (address + port). You exist
  in the phone book now.
- **LISTENING** -- you're sitting by the phone, waiting for incoming calls.
  Only servers do this.
- **CONNECTED** -- you're on an active call with someone. Data can flow back
  and forth.
- **CLOSED** -- you hung up. The call is over and the socket can't be used
  anymore.

These states always move in one direction. You can't go from CLOSED back to
LISTENING, just like you can't un-hang-up a phone. If you want to accept more
calls, you need a new socket.

### Handling Multiple Clients

Here's a neat detail: the server's original socket stays in the LISTENING state
even after it accepts a connection. Each call to `accept()` creates a brand-new
**peer socket** that handles that one conversation. The listening socket keeps
waiting for more calls.

Think of it like a call centre. The main phone number rings at the front desk.
When a customer calls, the receptionist picks up and transfers them to an
available operator (a new peer socket). The main line stays open for the next
caller. The server can handle as many clients as it wants this way.

### Data Buffers -- The In-Memory Network

Our sockets don't use a real network. There are no cables, no Wi-Fi signals,
no TCP packets flying around. Instead, when two sockets are connected, PyOS
creates two **in-memory buffers** between them -- one for each direction. When
socket A sends data, it goes into a buffer. When socket B calls `recv()`, it
pulls data from that buffer.

This is a simplification, but it teaches the real concept perfectly. Real
sockets work the same way from the programmer's perspective -- you call
`send()` and `recv()` and data flows back and forth. The only difference is
that real sockets push data through network hardware instead of a Python
`deque`.

### The Socket Manager

Just like the `DeviceManager` keeps track of all devices, the `SocketManager`
keeps track of all sockets. It handles the behind-the-scenes work that a real
OS kernel would do:

- Creating sockets and assigning them unique IDs.
- Matching `connect()` calls to the right listening socket.
- Creating peer sockets when a server calls `accept()`.
- Setting up the bidirectional data buffers for each connection.
- Routing `send()` and `recv()` calls to the correct buffers.

In a real OS, this logic lives deep in the **network stack** -- a complex set
of layers that handle everything from raw electrical signals to high-level
protocols like HTTP. PyOS strips all that away and gives you just the socket
layer, which is the part your programs actually interact with.

---

## 5. DNS -- Name Resolution (`io/dns.py`)

### The Phone Book Analogy

Imagine you want to call your friend Sarah. You know her name, but you don't
know her phone number. So you open the phone book, find "Sarah," and read
the number next to her name. Now you can dial it.

**DNS** (Domain Name System) does exactly the same thing, but for the internet.
When you type `www.example.com` into a browser, your computer doesn't know
where that website lives -- it only understands numeric **IP addresses** like
`93.184.216.34`. So it asks a DNS server: "What's the phone number for
www.example.com?" The DNS server looks it up and says "93.184.216.34." Now
your computer knows where to connect.

### How It Works in PyOS

PyOS simulates DNS with a `DnsResolver` -- a local phone book that the kernel
owns. Each entry is called an **A record** (the "A" stands for "Address").
An A record maps a hostname to an IP address, just like a phone book maps
a name to a phone number.

You can:

- **Register** -- add a new entry: `dns register example.com 93.184.216.34`
- **Lookup** -- find the IP for a name: `dns lookup example.com`
- **Remove** -- delete an entry: `dns remove example.com`
- **List** -- see all entries: `dns list`
- **Flush** -- erase everything: `dns flush`

When the kernel boots, it automatically registers `localhost -> 127.0.0.1`.
That's the computer talking to itself -- like finding your own number in the
phone book.

### DNS Over Sockets -- How Queries Really Travel

Here's something cool: DNS queries don't just magically appear at the server.
They travel over **sockets**, just like any other network communication. In the
real world, DNS uses port 53.

The `dns demo` command shows this in action:

1. A client socket connects to a DNS server socket on port 53.
2. The client sends a text query: `QUERY A example.com`
3. The server receives the query, looks up the hostname in the phone book,
   and sends back: `ANSWER example.com 93.184.216.34`
4. The client reads the answer.

This is called **protocol layering** -- DNS is a protocol that runs *on top of*
sockets. The socket handles the "how do I send bytes from here to there" part,
and DNS handles the "what do those bytes mean" part. It's like how a phone call
(the socket) carries a conversation (the protocol) -- the phone doesn't care
what language you speak, and the language doesn't care what kind of phone
you're using.

### A Records -- Keeping It Simple

Real DNS has many record types: A records (IPv4 addresses), AAAA records (IPv6),
MX records (email servers), CNAME records (aliases), and more. PyOS only
implements A records because they're the most fundamental and the easiest to
understand. Once you get the concept of "name -> number," all the other record
types are just variations on the same theme.

---

## 6. HTTP -- Talking on the Web (`io/http.py`)

### The Restaurant Analogy

Imagine a restaurant. You (the **client**) sit down and read the menu. When
you're ready, you fill out an order form and hand it to the waiter. The waiter
(the **socket**) carries the order form to the kitchen (the **server**). The
kitchen prepares your food, writes a receipt, and the waiter carries the receipt
back to your table.

**HTTP** (Hypertext Transfer Protocol) works exactly like this. When you visit
a website, your browser (the client) writes an **HTTP request** -- an order
form -- and sends it to a web server. The server reads the request, figures out
what you're asking for, and sends back an **HTTP response** -- the receipt,
which includes the actual web page (or an error message).

The important thing is that the order form has a **specific format** that
everyone agrees on. That agreed-upon format is the **protocol**. Without it,
the kitchen wouldn't know how to read your order, and you wouldn't know how to
read the receipt.

### Requests -- The Order Form

An HTTP request has three parts:

1. **Method** -- what you're asking for:
   - `GET` means "give me this resource" (like asking for a menu item)
   - `POST` means "here's some data for you" (like submitting a form)

2. **Path** -- which resource you want (like `/index.html` or `/images/logo.png`)

3. **Headers** -- extra information, like metadata. For example, `Host: example.com`
   tells the server which website you're trying to reach (important because one
   server can host many websites).

Here's what a real HTTP request looks like "on the wire" -- the raw bytes that
travel over the socket:

```
GET /index.html HTTP/1.0
Host: localhost

```

That's it. A method, a path, a version, some headers, and a blank line at the
end. Simple.

### Responses -- The Receipt

An HTTP response also has a specific format:

1. **Status code** -- a number that tells you what happened:
   - `200 OK` -- success! Here's what you asked for.
   - `404 Not Found` -- that resource doesn't exist.
   - `400 Bad Request` -- your order form was filled out wrong.
   - `500 Internal Server Error` -- the kitchen caught fire (something went
     wrong on the server's end).

2. **Headers** -- metadata like `Content-Length: 42` (how many bytes are in the
   body) or `Content-Type: text/html` (what kind of data this is).

3. **Body** -- the actual content (the web page, the image, the data).

Here's what a real response looks like:

```
HTTP/1.0 200 OK
Content-Type: text/html
Content-Length: 25

<h1>Welcome to PyOS!</h1>
```

### Protocol Layering -- HTTP on Top of Sockets

Here's the key insight: HTTP doesn't know or care *how* bytes get from point A
to point B. That's the socket's job. And sockets don't know or care *what* the
bytes mean. That's HTTP's job.

This separation is called **protocol layering**. Each layer does one thing well
and relies on the layer below it for the rest:

```
  HTTP      (application layer -- what do the bytes mean?)
    |
  Sockets   (transport layer -- how do bytes get there?)
    |
  Buffers   (in-memory simulation of a network)
```

In a real OS, there are even more layers (TCP, IP, Ethernet). PyOS simplifies
this to just HTTP on sockets on in-memory buffers. But the *concept* is
identical.

### The `http demo` Command

The `http demo` command walks through an end-to-end HTTP exchange:

1. Creates a file in the filesystem (`/www/index.html`)
2. Registers a DNS name for the web server
3. Sets up a server socket (bind, listen) and a client socket (connect)
4. Client builds an HTTP GET request, formats it, and sends it over the socket
5. Server receives the raw bytes, parses the request, reads the file from the
   filesystem, builds an HTTP 200 OK response, and sends it back
6. Client receives and parses the response, displaying the file contents
7. Then repeats with a file that doesn't exist, showing a 404 Not Found

Every socket operation goes through **syscalls** -- demonstrating full kernel
integration. This is real protocol layering in action: DNS resolves the name,
sockets carry the bytes, and HTTP gives those bytes meaning.

### HTTP Is User-Space

One important design decision: HTTP is **not** a kernel subsystem. In PyOS (and
in real operating systems), the kernel owns sockets, but HTTP is just a library
of functions that any program can use. The kernel doesn't know or care about
HTTP -- it just moves bytes. This mirrors reality: your web browser is a regular
program, not part of the kernel.

---

## Putting It All Together

These six systems -- devices, IPC, disk scheduling, networking, DNS, and HTTP --
cover how the OS connects programs to the outside world and to each other.

- **Devices** give programs a simple, uniform way to talk to hardware. Read and
  write -- that's it. The OS handles the messy details of each specific piece
  of hardware behind the scenes.

- **IPC** lets [processes](processes.md) share data even though they live in
  isolated [memory](memory.md) spaces. Pipes handle byte streams, message
  queues handle structured messages, and shared memory lets processes read
  and write the same underlying bytes with zero copying.

- **Disk scheduling** decides the smartest order to serve disk requests, so
  the read head doesn't waste time zigzagging. The choice of algorithm is a
  trade-off between fairness and efficiency.

- **Networking** lets processes talk to each other across a connection, using
  the familiar socket lifecycle: create, bind, listen, accept, send, receive,
  close.

- **DNS** translates human-readable hostnames into numeric IP addresses,
  acting as the internet's phone book. Queries travel over sockets,
  demonstrating how protocols layer on top of each other.

- **HTTP** adds meaning to the raw bytes that sockets carry. Clients send
  structured requests (GET /page) and servers send structured responses
  (200 OK with a body). It's the top layer in our protocol stack.

All of these follow a common pattern in OS design: give programs a **simple
interface** (read, write, send, receive) and let the OS handle the complicated
stuff underneath. Your program says "send this data," and it doesn't need to
know whether it's going to a printer, a pipe, a disk, or another computer
halfway around the world.

---

## Where to Go Next

- [What Is an OS?](what-is-an-os.md) -- The big picture of how an OS works
- [Processes](processes.md) -- How the OS runs programs and shares the processor
- [Memory](memory.md) -- How the OS hands out and protects memory
- [Filesystem](filesystem.md) -- How files and folders are organized and stored
- [The Kernel](kernel-and-syscalls.md) -- The core of the OS and how programs talk to it
