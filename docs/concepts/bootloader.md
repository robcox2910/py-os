# The Boot Chain

When you press the power button on a real computer, quite a lot happens before
you see a login screen. This page explains the journey from "power on" to
"ready to use."

---

## 1. The Power Button Analogy

Imagine you're opening a school building in the morning. You can't just throw
the doors open and hope for the best. There's a whole sequence:

1. **Security guard checks the building** -- lights work? Water running? Doors
   not broken? This is the **firmware POST** (Power-On Self-Test).
2. **Janitor fetches today's plan** -- they go to the supply closet (the disk)
   and pull out a file called "Today's School Plan." This is the **bootloader**
   loading the **kernel image**.
3. **Principal sets up departments** -- using the plan, the principal
   (the kernel) sets up each department one by one: memory, files, users,
   devices, scheduler. This is the **kernel boot**.
4. **Vice principal opens the front desk** -- students can now check in. This
   is the **init process** starting the **shell** so you can type commands.

In a real computer, the chain looks like this:

```
Power on
   |
   v
Firmware POST     -- "Is the hardware OK?"
   |
   v
Bootloader        -- "Find and load the kernel from disk"
   |
   v
Kernel boot       -- "Set up all subsystems"
   |
   v
Init (PID 1)      -- "Start the first user-facing process"
   |
   v
Shell prompt      -- "Ready for your commands!"
```

---

## 2. Firmware POST

POST stands for **Power-On Self-Test**. Before doing anything else, the
computer's firmware (a tiny program baked into the motherboard) checks that the
essential hardware is working:

- **Memory** -- are there enough memory frames available?
- **Disk** -- can we read from the storage device?
- **Devices** -- are basic devices responding?

If any check fails, the computer cannot boot. On real machines, you might hear
a series of beeps or see an error code. In PyOS, a `BootError` is raised with
a message explaining what went wrong.

In PyOS, you can see the POST results in the boot log:

```
[POST] Memory: 64 frames ... OK
[POST] Disk: accessible ... OK
[POST] Devices: ready ... OK
```

---

## 3. The Bootloader

Once POST passes, the bootloader takes over. Its job is simple but critical:
**find the kernel on disk and load it into memory**.

On a real PC, the bootloader (like GRUB or systemd-boot) reads a file called
something like `/boot/vmlinuz` from the hard drive. This file is the **kernel
image** -- the compiled kernel binary plus its configuration.

In PyOS, the `Bootloader` class does the same thing. It can load a kernel
image from a JSON file on disk, or use sensible defaults. The kernel image
contains:

- **version** -- which version of the kernel to boot (e.g. "0.1.0")
- **total_frames** -- how much memory the kernel should manage
- **num_cpus** -- how many CPUs the kernel should use (default 1)
- **default_policy** -- which scheduling policy to start with
- **boot_args** -- extra configuration settings

```
[BOOT] Loading kernel image v0.1.0 ... OK
```

---

## 4. Kernel Boot

With the kernel image loaded, the kernel itself takes over. It initializes
every subsystem in a specific order (because each one depends on the ones
before it):

```
[OK] Logger
[OK] Memory manager (64 frames)
[OK] Slab allocator
[OK] File system (journaled)
[OK] User manager
[OK] Environment
[OK] Device manager
[OK] DNS resolver
[OK] Network stack
[OK] Sync primitives
[OK] Scheduler (FCFS)
[OK] /proc filesystem
[OK] Init process (PID ...)
```

This is exactly what we covered in the
[Kernel and System Calls](kernel-and-syscalls.md) page -- the boot sequence
hasn't changed, we've just made it visible through the boot log.

---

## 5. The Init Process

At the very end of the kernel boot, something special happens: the kernel
creates a process called **init**. This is the first process in the system,
and every other process is a child (or grandchild, or great-grandchild)
of init.

In real Unix/Linux:
- init always gets **PID 1**
- It is the root of the process tree
- If a process's parent dies, init "adopts" the orphaned children
- init is the last process to stop during shutdown

In PyOS, the kernel creates init the same way:

```python
init = Process(name="init", priority=0)
init.admit()
scheduler.add(init)
```

Notice that init doesn't allocate memory -- it's a lightweight sentinel that
just represents the root of the process tree. When you create a new process
with `create_process()`, it automatically becomes a child of init (unless
you specify a different parent). This means `pstree` always shows init at
the top.

---

## 6. The dmesg Command

In Linux, the `dmesg` command shows the kernel's boot messages. It's like
reading the school's morning checklist after everything is already open --
you can see exactly what happened during startup.

PyOS has the same command:

```
$ dmesg
[OK] Logger
[OK] Memory manager (64 frames)
[OK] Slab allocator
[OK] File system (journaled)
...
```

Behind the scenes, `dmesg` uses the `SYS_DMESG` syscall (number 210) to
fetch the boot log from the kernel.

There's also `SYS_BOOT_INFO` (number 211) that returns metadata about the
boot: the init process PID, system uptime, and kernel version.

---

## 7. The Boot Chain in PyOS Code

Here's how the REPL brings everything together:

```python
bootloader = Bootloader()
kernel = bootloader.boot()    # POST -> load image -> kernel.boot()
shell = Shell(kernel=kernel)
print(format_boot_log(bootloader.boot_log + kernel.dmesg()))
```

The `Bootloader.boot()` method runs through all four stages:

1. **FIRMWARE** -- run POST, check hardware
2. **BOOTLOADER** -- load the kernel image
3. **KERNEL** -- create a `Kernel` and call `boot()`
4. **USERSPACE** -- return the running kernel

You can track which stage the bootloader is in via its `stage` property,
which returns a `BootStage` enum value.

---

## Where to Go Next

- [Kernel and System Calls](kernel-and-syscalls.md) -- What happens after boot
- [Processes](processes.md) -- How the OS runs programs (starting from init)
- [What Is an Operating System?](what-is-an-os.md) -- The big picture
