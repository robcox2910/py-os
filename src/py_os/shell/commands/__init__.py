"""Shell commands, one module per topic (files, processes, memory, ...)."""

from py_os.shell.commands.basics import BasicCommands
from py_os.shell.commands.devices import DeviceCommands
from py_os.shell.commands.files import FileCommands
from py_os.shell.commands.isolation import IsolationCommands
from py_os.shell.commands.learn import LearnCommands
from py_os.shell.commands.memory import MemoryCommands
from py_os.shell.commands.network import NetworkCommands
from py_os.shell.commands.processes import ProcessCommands
from py_os.shell.commands.sync import SyncCommands
from py_os.shell.commands.users import UserCommands

__all__ = [
    "BasicCommands",
    "DeviceCommands",
    "FileCommands",
    "IsolationCommands",
    "LearnCommands",
    "MemoryCommands",
    "NetworkCommands",
    "ProcessCommands",
    "SyncCommands",
    "UserCommands",
]
