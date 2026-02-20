"""Interactive REPL (Read-Eval-Print Loop) for the operating system.

The REPL is the terminal interface that brings the OS to life.  It
boots the kernel, creates a shell, and enters the classic loop:

    1. **Read** — display a prompt and read user input.
    2. **Eval** — pass the command to ``shell.execute()``.
    3. **Print** — display the result.
    4. **Loop** — repeat until the shell returns the exit sentinel.

This module keeps the I/O loop separate from the shell logic.  The
shell is fully testable (returns strings, no I/O); the REPL is the
thin I/O wrapper that connects it to ``stdin``/``stdout``.

The helper functions (``build_prompt``, ``boot_banner``) are pure and
testable.  The ``run()`` function is the I/O entrypoint.
"""

from py_os.kernel import Kernel, KernelState
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber


def boot_banner() -> str:
    """Return the boot-up banner displayed when the OS starts."""
    return (
        "\n"
        "╔══════════════════════════════════════╗\n"
        "║           PyOS v0.1.0               ║\n"
        "║   A simulated operating system      ║\n"
        "╚══════════════════════════════════════╝\n"
        "\n"
        "Booting kernel...\n"
        "  [OK] Memory manager\n"
        "  [OK] File system\n"
        "  [OK] User manager\n"
        "  [OK] Scheduler\n"
        "Kernel running. Type 'help' for commands, 'exit' to quit.\n"
    )


def build_prompt(kernel: Kernel) -> str:
    """Build the shell prompt string showing the current user.

    Args:
        kernel: The running kernel (used to look up the current user).

    Returns:
        A prompt string like ``root@pyos $ `` or ``alice@pyos $ ``.

    """
    if kernel.state is not KernelState.RUNNING:
        return "pyos $ "

    info: dict[str, object] = kernel.syscall(SyscallNumber.SYS_WHOAMI)
    return f"{info['username']}@pyos $ "


def run() -> None:
    """Boot the OS and run the interactive REPL.

    This is the main entrypoint.  It handles:
    - Kernel boot and shell creation.
    - The read-eval-print loop.
    - Graceful handling of Ctrl+C and Ctrl+D.
    - Clean shutdown.
    """
    kernel = Kernel()
    kernel.boot()
    shell = Shell(kernel=kernel)

    print(boot_banner())  # noqa: T201

    try:
        while kernel.state is KernelState.RUNNING:
            try:
                command = input(build_prompt(kernel))
            except EOFError:
                # Ctrl+D — graceful exit
                print()  # noqa: T201
                break

            result = shell.execute(command)
            if result == Shell.EXIT_SENTINEL:
                break
            if result:
                print(result)  # noqa: T201

    except KeyboardInterrupt:
        # Ctrl+C — graceful exit
        print("\nInterrupted.")  # noqa: T201

    finally:
        if kernel.state is KernelState.RUNNING:
            kernel.shutdown()
        print("System halted.")  # noqa: T201
