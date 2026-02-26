"""Interactive REPL (Read-Eval-Print Loop) for the operating system.

The REPL is the terminal interface that brings the OS to life.  It
boots the kernel via the bootloader, creates a shell, and enters
the classic loop:

    1. **Read** — display a prompt and read user input.
    2. **Eval** — pass the command to ``shell.execute()``.
    3. **Print** — display the result.
    4. **Loop** — repeat until the shell returns the exit sentinel.

This module keeps the I/O loop separate from the shell logic.  The
shell is fully testable (returns strings, no I/O); the REPL is the
thin I/O wrapper that connects it to ``stdin``/``stdout``.

The helper functions (``build_prompt``, ``format_boot_log``) are pure
and testable.  The ``run()`` function is the I/O entrypoint.
"""

import readline

from py_os.bootloader import Bootloader
from py_os.completer import Completer
from py_os.kernel import Kernel, KernelState
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber

_BANNER_WIDTH = 38


def format_boot_log(boot_log: list[str]) -> str:
    """Format the boot log into a displayable banner string.

    Args:
        boot_log: List of boot messages from the bootloader and kernel.

    Returns:
        A formatted string suitable for printing to the console.

    """
    border = "=" * _BANNER_WIDTH
    header = (
        f"\n  {border}\n            PyOS v0.1.0\n     A simulated operating system\n  {border}\n\n"
    )
    body = "\n".join(f"  {msg}" for msg in boot_log)
    footer = "\nKernel running. Type 'help' for commands, 'exit' to quit.\n"
    return header + body + footer


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
    - Bootloader chain (POST → load kernel image → kernel boot).
    - Shell creation.
    - The read-eval-print loop.
    - Graceful handling of Ctrl+C and Ctrl+D.
    - Clean shutdown.
    """
    bootloader = Bootloader()
    kernel = bootloader.boot()
    shell = Shell(kernel=kernel)

    # Wire up tab completion via readline.
    completer = Completer(shell)
    readline.set_completer(completer.complete)
    readline.set_completer_delims(" \t")
    readline.parse_and_bind("tab: complete")

    print(format_boot_log(bootloader.boot_log + kernel.dmesg()))  # noqa: T201

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
