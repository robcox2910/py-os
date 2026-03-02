# Containers

## What Is a Container?

Imagine your school has a big building with classrooms, a library, and a
canteen. Now imagine the school needs more space — but instead of building
a whole new school, they put **portable classrooms** in the car park.

Each portable classroom has:

- Its own **door number** (even though the school still tracks rooms globally)
- Its own **storage cupboard** (separate from the main building's storage)
- Its own **phone line** (so calls don't mix with the main office)

But they all share the same building — the same electricity, the same
caretaker, and the same headteacher.

**That's exactly what containers are.** A container is a lightweight,
isolated environment that runs inside the main operating system (the
"school building"). Each container gets its own private view of the system,
even though they all share the same kernel.

## Real-World Containers

You've probably heard of **Docker** — it's the most popular container
tool in the world. Companies use containers to:

- Run websites without them interfering with each other
- Test software in clean, isolated environments
- Package applications so they work the same everywhere

Under the hood, Docker uses **Linux namespaces** — the same concept
our PyOS containers implement!

## The Three Namespaces

A container gets its isolation from three **namespaces**:

```
┌─────────────────────────────────────────────────────────┐
│                     Host Kernel                          │
│                                                          │
│  ┌─────────────────────┐   ┌─────────────────────┐      │
│  │   Container "web"    │   │   Container "db"     │      │
│  │                      │   │                      │      │
│  │  PID Namespace       │   │  PID Namespace       │      │
│  │  ├── VPID 1 (init)   │   │  ├── VPID 1 (init)   │      │
│  │  └── VPID 2 (worker) │   │  └── VPID 2 (query)  │      │
│  │                      │   │                      │      │
│  │  Mount Namespace     │   │  Mount Namespace     │      │
│  │  / → /containers/web │   │  / → /containers/db  │      │
│  │                      │   │                      │      │
│  │  Network Namespace   │   │  Network Namespace   │      │
│  │  (own sockets + DNS) │   │  (own sockets + DNS) │      │
│  └─────────────────────┘   └─────────────────────┘      │
└─────────────────────────────────────────────────────────┘
```

### 1. PID Namespace

Every container has its own numbering for processes. The first process
inside a container is always **PID 1** — just like a freshly booted
computer.

But the kernel still tracks the "real" PID. So a process might be:

- **VPID 1** inside the container (the container thinks it's the first process)
- **Real PID 47** in the kernel (the kernel knows the truth)

Think of it like a hotel: Room 1 in every building is "Room 1" to the
guests, but the hotel chain tracks them as "Building A Room 1",
"Building B Room 1", etc.

### 2. Mount Namespace

Each container has its own **filesystem root**. When a process inside
the container asks for `/data/file.txt`, the kernel translates that to
something like `/containers/web/data/file.txt` on the real filesystem.

The container can't see files outside its root — it's like having your
own private filing cabinet that only you can access.

### 3. Network Namespace

Each container gets its own:

- **Socket manager** — for creating network connections
- **DNS resolver** — for looking up hostnames

This means two containers can both listen on the same port without
conflicting, because their network stacks are completely separate.

## Container Lifecycle

```
CREATED  ──>  RUNNING  ──>  STOPPED
   │                           │
   └── (never started) ────────┘
```

1. **CREATED** — The container exists but hasn't run anything yet
2. **RUNNING** — At least one process is executing inside
3. **STOPPED** — The container has been shut down

## Try It in the Shell

```
PyOS> container create web          # Create a new container
Created container 'web' (state: created)

PyOS> container create db           # Create another one
Created container 'db' (state: created)

PyOS> container list                # See all containers
NAME        STATE      PROCS  FS_ROOT
web         created    0      /containers/web
db          created    0      /containers/db

PyOS> container exec web hello      # Run a program inside
VPID 1 in 'web':
Hello from PyBin!

PyOS> container info web            # See namespace details
Container: web
  State: running
  Processes: 1
  FS root: /containers/web
  PID namespace: [1]
  Network: {'sockets': 0, 'dns_records': 0}

PyOS> container destroy web         # Clean up
Destroyed container 'web'

PyOS> container demo                # Run a full demonstration
```

## Why Does This Matter?

Containers changed how the entire internet works. Before containers,
every website needed its own server (or at least its own virtual machine).
Containers let you run hundreds of isolated applications on the same
computer, each thinking it has the whole machine to itself.

Understanding namespaces — PID isolation, filesystem isolation, network
isolation — is understanding how modern cloud computing works. Every time
you use a website, there's a good chance it's running inside a container
somewhere!

## Where to Go Next

- [Processes](processes.md) -- How processes work inside and outside containers
- [Filesystem](filesystem.md) -- Mount namespaces build on the filesystem
- [Inter-Machine Networking](inter-machine-networking.md) -- Connecting containers across machines

## Key Terms

| Term | Definition |
|------|-----------|
| **Container** | A lightweight isolated environment that shares the host kernel but has its own view of processes, files, and network |
| **Namespace** | A mechanism that gives a container its own private copy of a system resource (PIDs, mounts, network) |
| **PID namespace** | Gives the container its own process IDs -- PID 1 inside may be PID 42 on the host |
| **Mount namespace** | Gives the container its own filesystem root -- it can only see its own files |
| **Network namespace** | Gives the container its own sockets and DNS -- network traffic is isolated |
| **Virtual PID (VPID)** | The process ID as seen inside the container (different from the real PID) |
