"""Bootloader — simulated firmware POST and boot chain.

Every real computer follows a boot chain before you see a shell prompt:

    Firmware POST → Bootloader → Kernel → Userspace

Think of it like opening a school building each morning:

1. **Firmware POST** — Security guard checks lights, water, doors.
2. **Bootloader** — Janitor fetches "Today's School Plan" from the
   supply closet (disk) and hands it to the principal.
3. **Kernel boot** — Principal sets up each department from the plan.
4. **Userspace** — Vice principal opens the front desk (shell) so
   students can check in.

This module simulates that chain so you can see what happens between
pressing the power button and getting a shell prompt.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from py_os.kernel import Kernel

if TYPE_CHECKING:
    from pathlib import Path


class BootStage(StrEnum):
    """Represent the current phase of the boot chain.

    The boot process moves through these stages in order:
    FIRMWARE → BOOTLOADER → KERNEL → USERSPACE.
    """

    FIRMWARE = "firmware"
    BOOTLOADER = "bootloader"
    KERNEL = "kernel"
    USERSPACE = "userspace"


@dataclass(frozen=True)
class PostResult:
    """Capture the outcome of the firmware Power-On Self-Test (POST).

    POST checks that essential hardware works before the OS loads.
    If any check fails, the machine cannot boot safely.
    """

    memory_ok: bool
    disk_ok: bool
    devices_ok: bool
    messages: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        """Return True only if every hardware check passed."""
        return self.memory_ok and self.disk_ok and self.devices_ok


@dataclass(frozen=True)
class KernelImage:
    """Represent the kernel binary stored on disk.

    In a real system the bootloader reads the kernel image from a
    partition (e.g. ``/boot/vmlinuz``).  Our image carries the
    configuration the kernel needs to initialise itself.
    """

    version: str
    total_frames: int
    default_policy: str
    boot_args: dict[str, str] = field(default_factory=lambda: {})  # noqa: PIE807
    num_cpus: int = 1


class BootError(RuntimeError):
    """Raise when the boot chain cannot continue.

    Examples: POST failure, missing kernel image, corrupt image file.
    """


class Bootloader:
    """Simulate the firmware + bootloader that starts the kernel.

    Usage::

        bootloader = Bootloader()
        kernel = bootloader.boot()  # full chain, returns running kernel

    """

    def __init__(
        self,
        *,
        kernel_image_path: Path | None = None,
        total_frames: int = 64,
        num_cpus: int = 1,
    ) -> None:
        """Create a bootloader with optional kernel image path.

        Args:
            kernel_image_path: Path to a JSON kernel image file.
                If None, a default image is constructed in memory.
            total_frames: Default memory frame count (used when no
                image file is provided).
            num_cpus: Number of CPUs to simulate (default 1).

        """
        self._kernel_image_path = kernel_image_path
        self._total_frames = total_frames
        self._num_cpus = num_cpus
        self._stage: BootStage = BootStage.FIRMWARE
        self._boot_log: list[str] = []
        self._kernel: Kernel | None = None

    @property
    def stage(self) -> BootStage:
        """Return the current boot stage."""
        return self._stage

    @property
    def boot_log(self) -> list[str]:
        """Return the accumulated boot log messages."""
        return list(self._boot_log)

    @property
    def kernel(self) -> Kernel | None:
        """Return the booted kernel, or None if boot has not completed."""
        return self._kernel

    def boot(self) -> Kernel:
        """Run the full boot chain and return a running kernel.

        Raises:
            BootError: If POST fails or the kernel image is missing.

        """
        # Stage 1: Firmware POST
        self._stage = BootStage.FIRMWARE
        post_result = self._run_post()
        if not post_result.passed:
            msg = "POST failed: " + ", ".join(post_result.messages)
            raise BootError(msg)
        self._boot_log.extend(f"[POST] {m}" for m in post_result.messages)

        # Stage 2: Load kernel image
        self._stage = BootStage.BOOTLOADER
        image = self._load_kernel_image()
        self._boot_log.append(f"[BOOT] Loading kernel image v{image.version} ... OK")

        # Stage 3: Boot kernel
        self._stage = BootStage.KERNEL
        kernel = Kernel(total_frames=image.total_frames, num_cpus=image.num_cpus)
        kernel.boot()
        self._kernel = kernel

        # Stage 4: Userspace ready
        self._stage = BootStage.USERSPACE
        return kernel

    def _run_post(self) -> PostResult:
        """Simulate the Power-On Self-Test.

        Check memory frames, disk accessibility, and device availability.
        """
        messages: list[str] = []
        memory_ok = self._total_frames > 0
        messages.append(
            f"Memory: {self._total_frames} frames ... " + ("OK" if memory_ok else "FAIL")
        )

        # Disk is always accessible in our simulation
        disk_ok = True
        messages.append("Disk: accessible ... OK")

        # Devices are always available in our simulation
        devices_ok = True
        messages.append("Devices: ready ... OK")

        return PostResult(
            memory_ok=memory_ok,
            disk_ok=disk_ok,
            devices_ok=devices_ok,
            messages=tuple(messages),
        )

    def _load_kernel_image(self) -> KernelImage:
        """Load the kernel image from a JSON file or construct defaults.

        Raises:
            BootError: If the image file is specified but cannot be read.

        """
        if self._kernel_image_path is not None:
            try:
                data = json.loads(self._kernel_image_path.read_text())
                return KernelImage(
                    version=data.get("version", "0.1.0"),
                    total_frames=data.get("total_frames", self._total_frames),
                    default_policy=data.get("default_policy", "fcfs"),
                    boot_args=data.get("boot_args", {}),
                    num_cpus=data.get("num_cpus", self._num_cpus),
                )
            except (OSError, json.JSONDecodeError) as e:
                msg = f"Cannot load kernel image: {e}"
                raise BootError(msg) from e

        return KernelImage(
            version="0.1.0",
            total_frames=self._total_frames,
            default_policy="fcfs",
            num_cpus=self._num_cpus,
        )
