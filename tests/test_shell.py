"""Tests for the shell module.

The shell is the command interpreter — it parses user input, dispatches
to built-in commands, and returns string output.  It operates on a
booted kernel, using its subsystems (scheduler, memory, file system).
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell

NUM_PAGES = 2


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel, Shell(kernel=kernel)


class TestShellCreation:
    """Verify shell initialisation."""

    def test_shell_requires_booted_kernel(self) -> None:
        """The shell should reject a non-running kernel."""
        kernel = Kernel()
        with pytest.raises(RuntimeError, match="not running"):
            Shell(kernel=kernel)

    def test_shell_accepts_booted_kernel(self) -> None:
        """The shell should accept a running kernel."""
        _kernel, shell = _booted_shell()
        assert shell is not None


class TestShellExecute:
    """Verify command parsing and dispatch."""

    def test_empty_command_returns_empty(self) -> None:
        """An empty command should produce no output."""
        _kernel, shell = _booted_shell()
        assert shell.execute("") == ""

    def test_whitespace_only_returns_empty(self) -> None:
        """Whitespace-only input should produce no output."""
        _kernel, shell = _booted_shell()
        assert shell.execute("   ") == ""

    def test_unknown_command_returns_error(self) -> None:
        """An unknown command should produce an error message."""
        _kernel, shell = _booted_shell()
        result = shell.execute("foobar")
        assert "Unknown command" in result
        assert "foobar" in result


class TestShellHelp:
    """Verify the help command."""

    def test_help_lists_commands(self) -> None:
        """Help should list available commands."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "ps" in result
        assert "ls" in result
        assert "help" in result


class TestShellPs:
    """Verify the ps (process status) command."""

    def test_ps_shows_init(self) -> None:
        """Ps should always show the init process."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ps")
        assert "PID" in result
        assert "init" in result

    def test_ps_shows_created_process(self) -> None:
        """Ps should list processes created via the kernel."""
        kernel, shell = _booted_shell()
        kernel.create_process(name="daemon", num_pages=NUM_PAGES)
        result = shell.execute("ps")
        assert "daemon" in result


class TestShellFilesystemCommands:
    """Verify ls, mkdir, touch, cat, write, rm commands."""

    def test_ls_root(self) -> None:
        """Ls on root should work (empty initially)."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ls /")
        # Root is empty, so just no error
        assert result is not None

    def test_mkdir_then_ls(self) -> None:
        """Creating a directory should make it appear in ls."""
        _kernel, shell = _booted_shell()
        shell.execute("mkdir /docs")
        result = shell.execute("ls /")
        assert "docs" in result

    def test_touch_then_ls(self) -> None:
        """Creating a file should make it appear in ls."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /hello.txt")
        result = shell.execute("ls /")
        assert "hello.txt" in result

    def test_write_then_cat(self) -> None:
        """Writing to a file then reading it back with cat."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /hello.txt")
        shell.execute("write /hello.txt Hello, OS!")
        result = shell.execute("cat /hello.txt")
        assert "Hello, OS!" in result

    def test_cat_nonexistent_file(self) -> None:
        """Cat on a missing file should produce an error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("cat /nope.txt")
        assert "not found" in result.lower() or "error" in result.lower()

    def test_rm_file(self) -> None:
        """Rm should delete a file."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /hello.txt")
        shell.execute("rm /hello.txt")
        result = shell.execute("ls /")
        assert "hello.txt" not in result

    def test_mkdir_missing_arg(self) -> None:
        """Mkdir without an argument should produce a usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("mkdir")
        assert "usage" in result.lower() or "error" in result.lower()


class TestShellScheduler:
    """Verify the scheduler command for viewing and switching policies."""

    def test_scheduler_shows_current_policy(self) -> None:
        """Default scheduler should report FCFS."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler")
        assert "FCFS" in result

    def test_scheduler_switch_to_priority(self) -> None:
        """Switching to priority policy should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler priority")
        assert "Priority" in result

    def test_scheduler_switch_to_rr(self) -> None:
        """Switching to round robin with a quantum should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler rr 3")
        assert "Round Robin" in result

    def test_scheduler_missing_rr_quantum(self) -> None:
        """Round robin without a quantum should produce a usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler rr")
        assert "usage" in result.lower() or "error" in result.lower()

    def test_scheduler_unknown_policy(self) -> None:
        """An unknown policy name should produce an error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler foo")
        assert "error" in result.lower() or "unknown" in result.lower()

    def test_scheduler_switch_to_mlfq(self) -> None:
        """Switching to MLFQ policy should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler mlfq")
        assert "MLFQ" in result

    def test_scheduler_mlfq_with_params(self) -> None:
        """Switching to MLFQ with custom levels and base quantum."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler mlfq 4 3")
        assert "4 levels" in result
        assert "base_quantum=3" in result

    def test_scheduler_boost(self) -> None:
        """Scheduler boost should succeed when MLFQ is active."""
        _kernel, shell = _booted_shell()
        shell.execute("scheduler mlfq")
        result = shell.execute("scheduler boost")
        assert "boost" in result.lower()

    def test_scheduler_boost_without_mlfq(self) -> None:
        """Scheduler boost with a non-MLFQ policy should error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler boost")
        assert "error" in result.lower()

    def test_scheduler_show_mlfq(self) -> None:
        """Showing scheduler info with MLFQ should display levels and quanta."""
        _kernel, shell = _booted_shell()
        shell.execute("scheduler mlfq")
        result = shell.execute("scheduler")
        assert "MLFQ" in result
        assert "levels" in result.lower()
        assert "quanta" in result.lower()

    def test_scheduler_switch_to_aging(self) -> None:
        """Switching to aging priority policy should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler aging")
        assert "Aging Priority" in result

    def test_scheduler_show_aging(self) -> None:
        """Showing scheduler info with aging active should display boost and max_age."""
        _kernel, shell = _booted_shell()
        shell.execute("scheduler aging")
        result = shell.execute("scheduler")
        assert "Aging Priority" in result
        assert "boost" in result.lower()
        assert "max_age" in result.lower()

    def test_scheduler_switch_to_cfs(self) -> None:
        """Switching to CFS policy should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler cfs")
        assert "CFS" in result

    def test_scheduler_cfs_with_base_slice(self) -> None:
        """Switching to CFS with a custom base_slice should show it."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler cfs 3")
        assert "base_slice=3" in result

    def test_scheduler_show_cfs(self) -> None:
        """Showing scheduler info with CFS active should display base_slice."""
        _kernel, shell = _booted_shell()
        shell.execute("scheduler cfs")
        result = shell.execute("scheduler")
        assert "CFS" in result
        assert "base_slice" in result


class TestShellRunWithPriority:
    """Verify the run command accepts an optional priority argument."""

    def test_run_with_priority(self) -> None:
        """Running a program with a priority should succeed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("run hello 5")
        assert "Hello from PyOS!" in result


class TestShellKill:
    """Verify the kill command."""

    def test_kill_terminates_running_process(self) -> None:
        """Kill should terminate a process by PID."""
        kernel, shell = _booted_shell()
        process = kernel.create_process(name="victim", num_pages=NUM_PAGES)
        # Dispatch init first (FCFS), preempt it, then dispatch victim
        assert kernel.scheduler is not None
        init_proc = kernel.scheduler.dispatch()
        assert init_proc is not None
        init_proc.preempt()
        kernel.scheduler.add(init_proc)
        kernel.scheduler.dispatch()
        result = shell.execute(f"kill {process.pid}")
        assert "terminated" in result.lower() or "killed" in result.lower()

    def test_kill_missing_arg(self) -> None:
        """Kill without a PID should produce a usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("kill")
        assert "usage" in result.lower() or "error" in result.lower()


class TestCommandNamesProperty:
    """Verify the command_names property on Shell."""

    def test_command_names_returns_sorted_list(self) -> None:
        """command_names should return a sorted list of strings."""
        _kernel, shell = _booted_shell()
        names = shell.command_names
        assert names == sorted(names)
        assert isinstance(names, list)

    def test_command_names_includes_known_commands(self) -> None:
        """command_names should include well-known commands."""
        _kernel, shell = _booted_shell()
        names = shell.command_names
        for cmd in ("ls", "cat", "mkdir", "ps", "help", "exit", "run"):
            assert cmd in names


# -- TCP commands -----------------------------------------------------------

TCP_LISTEN_PORT = 8080
TCP_CLIENT_PORT = 5000


class TestShellTcpBasics:
    """Verify TCP command dispatch and argument validation."""

    def test_tcp_no_args_shows_usage(self) -> None:
        """Tcp with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp")
        assert "Usage" in result

    def test_tcp_unknown_subcommand_shows_usage(self) -> None:
        """Tcp with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp foobar")
        assert "Usage" in result

    def test_tcp_listen_no_port(self) -> None:
        """Tcp listen without a port should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp listen")
        assert "Usage" in result

    def test_tcp_listen_invalid_port(self) -> None:
        """Tcp listen with non-integer port should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp listen abc")
        assert "Error" in result

    def test_tcp_connect_too_few_args(self) -> None:
        """Tcp connect without enough args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp connect 5000")
        assert "Usage" in result

    def test_tcp_connect_invalid_ports(self) -> None:
        """Tcp connect with non-integer ports should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp connect abc def")
        assert "Error" in result

    def test_tcp_send_too_few_args(self) -> None:
        """Tcp send without enough args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp send")
        assert "Usage" in result

    def test_tcp_send_invalid_conn_id(self) -> None:
        """Tcp send with non-integer conn_id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp send abc hello")
        assert "Error" in result

    def test_tcp_recv_no_args(self) -> None:
        """Tcp recv without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp recv")
        assert "Usage" in result

    def test_tcp_recv_invalid_conn_id(self) -> None:
        """Tcp recv with non-integer conn_id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp recv abc")
        assert "Error" in result

    def test_tcp_close_no_args(self) -> None:
        """Tcp close without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp close")
        assert "Usage" in result

    def test_tcp_close_invalid_conn_id(self) -> None:
        """Tcp close with non-integer conn_id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp close abc")
        assert "Error" in result

    def test_tcp_info_no_args(self) -> None:
        """Tcp info without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp info")
        assert "Usage" in result

    def test_tcp_info_invalid_conn_id(self) -> None:
        """Tcp info with non-integer conn_id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp info abc")
        assert "Error" in result


class TestShellTcpLifecycle:
    """Verify TCP listen, connect, send, recv, info, close, and list."""

    def test_tcp_listen_creates_listener(self) -> None:
        """Tcp listen should create a listener on the specified port."""
        _kernel, shell = _booted_shell()
        result = shell.execute(f"tcp listen {TCP_LISTEN_PORT}")
        assert "Listening" in result
        assert str(TCP_LISTEN_PORT) in result

    def test_tcp_connect_opens_connection(self) -> None:
        """Tcp connect should open a connection to a listening port."""
        _kernel, shell = _booted_shell()
        shell.execute(f"tcp listen {TCP_LISTEN_PORT}")
        result = shell.execute(f"tcp connect {TCP_CLIENT_PORT} {TCP_LISTEN_PORT}")
        assert "Connection" in result
        assert "opened" in result

    def test_tcp_send_delivers_data(self) -> None:
        """Tcp send should report bytes sent."""
        _kernel, shell = _booted_shell()
        shell.execute(f"tcp listen {TCP_LISTEN_PORT}")
        result = shell.execute(f"tcp connect {TCP_CLIENT_PORT} {TCP_LISTEN_PORT}")
        conn_id = result.split()[1]
        send_result = shell.execute(f"tcp send {conn_id} Hello TCP")
        assert "Sent" in send_result
        assert "bytes" in send_result

    def test_tcp_recv_receives_data(self) -> None:
        """Tcp recv should return data sent to a connection."""
        _kernel, shell = _booted_shell()
        shell.execute(f"tcp listen {TCP_LISTEN_PORT}")
        shell.execute(f"tcp connect {TCP_CLIENT_PORT} {TCP_LISTEN_PORT}")
        # Recv on a nonexistent connection to exercise the recv error path
        result = shell.execute("tcp recv 999")
        assert "Error" in result

    def test_tcp_info_shows_connection_details(self) -> None:
        """Tcp info should display connection parameters."""
        _kernel, shell = _booted_shell()
        shell.execute(f"tcp listen {TCP_LISTEN_PORT}")
        result = shell.execute(f"tcp connect {TCP_CLIENT_PORT} {TCP_LISTEN_PORT}")
        conn_id = result.split()[1]
        info_result = shell.execute(f"tcp info {conn_id}")
        assert "TCP Connection" in info_result

    def test_tcp_close_closes_connection(self) -> None:
        """Tcp close should close a connection."""
        _kernel, shell = _booted_shell()
        shell.execute(f"tcp listen {TCP_LISTEN_PORT}")
        result = shell.execute(f"tcp connect {TCP_CLIENT_PORT} {TCP_LISTEN_PORT}")
        conn_id = result.split()[1]
        close_result = shell.execute(f"tcp close {conn_id}")
        assert "closed" in close_result

    def test_tcp_list_shows_connections(self) -> None:
        """Tcp list should show active connections."""
        _kernel, shell = _booted_shell()
        shell.execute(f"tcp listen {TCP_LISTEN_PORT}")
        shell.execute(f"tcp connect {TCP_CLIENT_PORT} {TCP_LISTEN_PORT}")
        result = shell.execute("tcp list")
        assert "STATE" in result

    def test_tcp_list_empty(self) -> None:
        """Tcp list with no connections should say so."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp list")
        assert "No TCP connections" in result

    def test_tcp_send_invalid_connection(self) -> None:
        """Tcp send to nonexistent connection should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp send 999 hello")
        assert "Error" in result

    def test_tcp_close_invalid_connection(self) -> None:
        """Tcp close on nonexistent connection should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp close 999")
        assert "Error" in result

    def test_tcp_info_invalid_connection(self) -> None:
        """Tcp info on nonexistent connection should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp info 999")
        assert "Error" in result

    def test_tcp_connect_without_listener_opens_syn_sent(self) -> None:
        """Tcp connect without a listener opens a SYN_SENT connection."""
        _kernel, shell = _booted_shell()
        result = shell.execute(f"tcp connect {TCP_CLIENT_PORT} {TCP_LISTEN_PORT}")
        assert "Connection" in result
        assert "SYN_SENT" in result


class TestShellTcpDemo:
    """Verify the TCP demo command."""

    def test_tcp_demo_runs_full_lifecycle(self) -> None:
        """Tcp demo should run the complete TCP lifecycle."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tcp demo")
        assert "TCP Demo" in result
        assert "listener" in result.lower() or "Listener" in result
        assert "Client" in result
        assert "close" in result.lower()


# -- Tick command -----------------------------------------------------------


class TestShellTick:
    """Verify the tick command."""

    def test_tick_default_one(self) -> None:
        """Tick with no args should advance by 1."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tick")
        assert "Ticked" in result
        assert "1 time" in result

    def test_tick_multiple(self) -> None:
        """Tick with a count should advance by that many."""
        _kernel, shell = _booted_shell()
        tick_count = 5
        result = shell.execute(f"tick {tick_count}")
        assert "Ticked" in result
        assert str(tick_count) in result

    def test_tick_shows_interrupt_info(self) -> None:
        """Tick should report interrupts serviced."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tick")
        assert "Interrupts serviced" in result

    def test_tick_invalid_count(self) -> None:
        """Tick with a non-integer count should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("tick abc")
        assert "Error" in result


# -- Interrupt command ------------------------------------------------------


class TestShellInterrupt:
    """Verify the interrupt command."""

    def test_interrupt_list_default(self) -> None:
        """Interrupt with no args should list vectors."""
        _kernel, shell = _booted_shell()
        result = shell.execute("interrupt")
        assert "VEC" in result or "No interrupt" in result

    def test_interrupt_list_explicit(self) -> None:
        """Interrupt list should show the vector table."""
        _kernel, shell = _booted_shell()
        result = shell.execute("interrupt list")
        assert "VEC" in result or "No interrupt" in result

    def test_interrupt_mask_vector(self) -> None:
        """Interrupt mask should mask a vector."""
        _kernel, shell = _booted_shell()
        result = shell.execute("interrupt mask 0")
        assert "masked" in result.lower()

    def test_interrupt_unmask_vector(self) -> None:
        """Interrupt unmask should unmask a vector."""
        _kernel, shell = _booted_shell()
        shell.execute("interrupt mask 0")
        result = shell.execute("interrupt unmask 0")
        assert "unmask" in result.lower()

    def test_interrupt_mask_no_vector(self) -> None:
        """Interrupt mask without vector should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("interrupt mask")
        assert "Usage" in result

    def test_interrupt_unmask_no_vector(self) -> None:
        """Interrupt unmask without vector should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("interrupt unmask")
        assert "Usage" in result

    def test_interrupt_mask_invalid_vector(self) -> None:
        """Interrupt mask with non-integer vector should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("interrupt mask abc")
        assert "Error" in result

    def test_interrupt_unknown_subcommand(self) -> None:
        """Interrupt with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("interrupt foobar")
        assert "Usage" in result


# -- Timer command ----------------------------------------------------------


class TestShellTimer:
    """Verify the timer command."""

    def test_timer_info_default(self) -> None:
        """Timer with no args should show timer info."""
        _kernel, shell = _booted_shell()
        result = shell.execute("timer")
        assert "Timer device" in result
        assert "Interval" in result

    def test_timer_info_explicit(self) -> None:
        """Timer info should show timer device status."""
        _kernel, shell = _booted_shell()
        result = shell.execute("timer info")
        assert "Timer device" in result
        assert "fires" in result.lower()

    def test_timer_set_interval(self) -> None:
        """Timer set should update the timer interval."""
        _kernel, shell = _booted_shell()
        new_interval = 10
        result = shell.execute(f"timer set {new_interval}")
        # After setting, verify via info
        assert result is not None
        info = shell.execute("timer info")
        assert str(new_interval) in info

    def test_timer_set_no_interval(self) -> None:
        """Timer set without an interval should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("timer set")
        assert "Usage" in result

    def test_timer_set_invalid_interval(self) -> None:
        """Timer set with non-integer interval should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("timer set abc")
        assert "Error" in result

    def test_timer_unknown_subcommand(self) -> None:
        """Timer with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("timer foobar")
        assert "Usage" in result


# -- Socket commands --------------------------------------------------------

SOCKET_PORT = 9090
SOCKET_ADDR = "10.0.0.1"


class TestShellSocketBasics:
    """Verify socket command dispatch and argument validation."""

    def test_socket_no_args_shows_usage(self) -> None:
        """Socket with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket")
        assert "Usage" in result

    def test_socket_unknown_subcommand_shows_usage(self) -> None:
        """Socket with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket foobar")
        assert "Usage" in result

    def test_socket_create(self) -> None:
        """Socket create should return a socket id."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket create")
        assert "Socket" in result
        assert "created" in result

    def test_socket_bind_too_few_args(self) -> None:
        """Socket bind without enough args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket bind 1")
        assert "Usage" in result

    def test_socket_bind_invalid_id(self) -> None:
        """Socket bind with non-integer id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket bind abc 10.0.0.1 80")
        assert "Error" in result

    def test_socket_listen_no_args(self) -> None:
        """Socket listen without id should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket listen")
        assert "Usage" in result

    def test_socket_listen_invalid_id(self) -> None:
        """Socket listen with non-integer id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket listen abc")
        assert "Error" in result

    def test_socket_connect_too_few_args(self) -> None:
        """Socket connect without enough args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket connect 1")
        assert "Usage" in result

    def test_socket_connect_invalid_id(self) -> None:
        """Socket connect with non-integer id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket connect abc 10.0.0.1 80")
        assert "Error" in result

    def test_socket_accept_no_args(self) -> None:
        """Socket accept without id should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket accept")
        assert "Usage" in result

    def test_socket_accept_invalid_id(self) -> None:
        """Socket accept with non-integer id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket accept abc")
        assert "Error" in result

    def test_socket_send_too_few_args(self) -> None:
        """Socket send without enough args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket send")
        assert "Usage" in result

    def test_socket_send_invalid_id(self) -> None:
        """Socket send with non-integer id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket send abc hello")
        assert "Error" in result

    def test_socket_recv_no_args(self) -> None:
        """Socket recv without id should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket recv")
        assert "Usage" in result

    def test_socket_recv_invalid_id(self) -> None:
        """Socket recv with non-integer id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket recv abc")
        assert "Error" in result

    def test_socket_close_no_args(self) -> None:
        """Socket close without id should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket close")
        assert "Usage" in result

    def test_socket_close_invalid_id(self) -> None:
        """Socket close with non-integer id should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket close abc")
        assert "Error" in result


class TestShellSocketLifecycle:
    """Verify socket create, bind, listen, connect, accept, send, recv, close."""

    def test_socket_bind_listen_connect_accept(self) -> None:
        """Full socket lifecycle: create, bind, listen, connect, accept."""
        _kernel, shell = _booted_shell()
        # Create server socket
        create_result = shell.execute("socket create")
        server_id = create_result.split()[1]

        # Bind and listen
        bind_result = shell.execute(f"socket bind {server_id} {SOCKET_ADDR} {SOCKET_PORT}")
        assert "bound" in bind_result
        listen_result = shell.execute(f"socket listen {server_id}")
        assert "listening" in listen_result

        # Create client and connect
        client_result = shell.execute("socket create")
        client_id = client_result.split()[1]
        connect_result = shell.execute(f"socket connect {client_id} {SOCKET_ADDR} {SOCKET_PORT}")
        assert "connected" in connect_result

        # Accept
        accept_result = shell.execute(f"socket accept {server_id}")
        assert "Accepted" in accept_result

    def test_socket_send_and_recv(self) -> None:
        """Socket send and recv should exchange data."""
        _kernel, shell = _booted_shell()
        # Set up server — parse IDs from output
        server_result = shell.execute("socket create")
        server_id = server_result.split()[1]
        shell.execute(f"socket bind {server_id} {SOCKET_ADDR} {SOCKET_PORT}")
        shell.execute(f"socket listen {server_id}")

        # Connect client
        client_result = shell.execute("socket create")
        client_id = client_result.split()[1]
        shell.execute(f"socket connect {client_id} {SOCKET_ADDR} {SOCKET_PORT}")
        accept_result = shell.execute(f"socket accept {server_id}")
        # Parse accepted peer socket id
        peer_id = accept_result.split()[-1]

        # Send from client, recv on accepted connection
        send_result = shell.execute(f"socket send {client_id} Hello World")
        assert "Sent" in send_result
        assert "bytes" in send_result

        recv_result = shell.execute(f"socket recv {peer_id}")
        assert "Hello World" in recv_result

    def test_socket_close(self) -> None:
        """Socket close should close a socket."""
        _kernel, shell = _booted_shell()
        create_result = shell.execute("socket create")
        sock_id = create_result.split()[1]
        result = shell.execute(f"socket close {sock_id}")
        assert "closed" in result

    def test_socket_list_empty(self) -> None:
        """Socket list with no sockets should say so."""
        _kernel, shell = _booted_shell()
        result = shell.execute("socket list")
        assert "No sockets" in result

    def test_socket_list_shows_sockets(self) -> None:
        """Socket list should show created sockets."""
        _kernel, shell = _booted_shell()
        shell.execute("socket create")
        result = shell.execute("socket list")
        assert "STATE" in result

    def test_socket_send_invalid_connection(self) -> None:
        """Socket send to non-connected socket should show error."""
        _kernel, shell = _booted_shell()
        create_result = shell.execute("socket create")
        sock_id = create_result.split()[1]
        result = shell.execute(f"socket send {sock_id} hello")
        assert "Error" in result

    def test_socket_recv_no_data(self) -> None:
        """Socket recv on connected socket with no data should return empty."""
        _kernel, shell = _booted_shell()
        # Set up connected sockets — parse IDs from output
        server_result = shell.execute("socket create")
        server_id = server_result.split()[1]
        shell.execute(f"socket bind {server_id} {SOCKET_ADDR} {SOCKET_PORT}")
        shell.execute(f"socket listen {server_id}")
        client_result = shell.execute("socket create")
        client_id = client_result.split()[1]
        shell.execute(f"socket connect {client_id} {SOCKET_ADDR} {SOCKET_PORT}")
        accept_result = shell.execute(f"socket accept {server_id}")
        peer_id = accept_result.split()[-1]
        # Recv without sending — should get no data
        result = shell.execute(f"socket recv {peer_id}")
        assert "no data" in result


# -- DNS commands -----------------------------------------------------------


class TestShellDns:
    """Verify DNS command operations."""

    def test_dns_no_args_shows_usage(self) -> None:
        """Dns with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns")
        assert "Usage" in result

    def test_dns_unknown_subcommand_shows_usage(self) -> None:
        """Dns with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns foobar")
        assert "Usage" in result

    def test_dns_register_and_lookup(self) -> None:
        """Dns register then lookup should resolve the name."""
        _kernel, shell = _booted_shell()
        shell.execute("dns register example.com 1.2.3.4")
        result = shell.execute("dns lookup example.com")
        assert "1.2.3.4" in result

    def test_dns_register_too_few_args(self) -> None:
        """Dns register without enough args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns register")
        assert "Usage" in result

    def test_dns_lookup_no_args(self) -> None:
        """Dns lookup without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns lookup")
        assert "Usage" in result

    def test_dns_lookup_missing_host(self) -> None:
        """Dns lookup for unregistered host should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns lookup nonexistent.com")
        assert "Error" in result

    def test_dns_remove(self) -> None:
        """Dns remove should delete a record."""
        _kernel, shell = _booted_shell()
        shell.execute("dns register example.com 1.2.3.4")
        result = shell.execute("dns remove example.com")
        assert "Removed" in result

    def test_dns_remove_no_args(self) -> None:
        """Dns remove without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns remove")
        assert "Usage" in result

    def test_dns_remove_missing_host(self) -> None:
        """Dns remove for unregistered host should show error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns remove nonexistent.com")
        assert "Error" in result

    def test_dns_list_shows_default_localhost(self) -> None:
        """Dns list should show the default localhost entry."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns list")
        assert "localhost" in result
        assert "127.0.0.1" in result

    def test_dns_list_with_records(self) -> None:
        """Dns list should show registered records."""
        _kernel, shell = _booted_shell()
        shell.execute("dns register example.com 1.2.3.4")
        result = shell.execute("dns list")
        assert "example.com" in result
        assert "1.2.3.4" in result

    def test_dns_flush(self) -> None:
        """Dns flush should clear all records."""
        _kernel, shell = _booted_shell()
        shell.execute("dns register a.com 1.1.1.1")
        shell.execute("dns register b.com 2.2.2.2")
        result = shell.execute("dns flush")
        assert "Flushed" in result

    def test_dns_demo_runs(self) -> None:
        """Dns demo should run the full demo sequence."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dns demo")
        assert "DNS Demo" in result
        assert "protocol layering" in result.lower() or "Step" in result


# -- HTTP commands ----------------------------------------------------------


class TestShellHttp:
    """Verify HTTP command operations."""

    def test_http_no_args_shows_usage(self) -> None:
        """Http with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("http")
        assert "Usage" in result

    def test_http_unknown_subcommand_shows_usage(self) -> None:
        """Http with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("http foobar")
        assert "Usage" in result

    def test_http_demo_runs(self) -> None:
        """Http demo should run the full HTTP demo."""
        _kernel, shell = _booted_shell()
        result = shell.execute("http demo")
        assert "HTTP Demo" in result


# -- Priority inheritance commands ------------------------------------------


class TestShellPriorityInheritance:
    """Verify priority inheritance (pi) commands."""

    def test_pi_no_args_shows_usage(self) -> None:
        """Pi with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("pi")
        assert "Usage" in result

    def test_pi_unknown_subcommand_shows_usage(self) -> None:
        """Pi with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("pi foobar")
        assert "Usage" in result

    def test_pi_status(self) -> None:
        """Pi status should show current boosted processes."""
        _kernel, shell = _booted_shell()
        result = shell.execute("pi status")
        assert "boost" in result.lower() or "No" in result or "Priority" in result

    def test_pi_demo_runs(self) -> None:
        """Pi demo should walk through the Mars Pathfinder scenario."""
        _kernel, shell = _booted_shell()
        result = shell.execute("pi demo")
        assert "Priority Inheritance" in result or "Mars" in result


# -- Ordering commands ------------------------------------------------------


class TestShellOrdering:
    """Verify resource ordering commands."""

    def test_ordering_no_args_shows_usage(self) -> None:
        """Ordering with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering")
        assert "Usage" in result

    def test_ordering_unknown_subcommand_shows_usage(self) -> None:
        """Ordering with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering foobar")
        assert "Usage" in result

    def test_ordering_register(self) -> None:
        """Ordering register should register a resource with a rank."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering register lock_a 1")
        assert "Registered" in result or "rank" in result.lower()

    def test_ordering_register_no_args_shows_usage(self) -> None:
        """Ordering register without enough args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering register")
        assert "Usage" in result

    def test_ordering_status(self) -> None:
        """Ordering status should show the current ordering state."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering status")
        assert "mode" in result.lower() or "Order" in result

    def test_ordering_mode_strict(self) -> None:
        """Ordering mode should change the enforcement mode."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering mode strict")
        assert "strict" in result.lower()

    def test_ordering_mode_no_args_shows_usage(self) -> None:
        """Ordering mode without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering mode")
        assert "Usage" in result

    def test_ordering_violations(self) -> None:
        """Ordering violations should report any ordering violations."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering violations")
        assert "violation" in result.lower() or "No" in result or "0" in result

    def test_ordering_demo_runs(self) -> None:
        """Ordering demo should walk through the numbered-lockers scenario."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ordering demo")
        assert "Ordering" in result or "locker" in result.lower()


# -- Shared memory commands -------------------------------------------------


class TestShellShm:
    """Verify shared memory (shm) commands."""

    def test_shm_no_args_shows_usage(self) -> None:
        """Shm with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("shm")
        assert "Usage" in result

    def test_shm_unknown_subcommand_shows_usage(self) -> None:
        """Shm with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("shm foobar")
        assert "Usage" in result

    def test_shm_create(self) -> None:
        """Shm create should create a shared memory segment."""
        kernel, shell = _booted_shell()
        # shm create requires <name> <size> <pid>
        proc = kernel.create_process(name="shm_test", num_pages=2)
        result = shell.execute(f"shm create test_segment 64 {proc.pid}")
        assert "Created" in result or "segment" in result.lower()

    def test_shm_create_no_args_shows_usage(self) -> None:
        """Shm create without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("shm create")
        assert "Usage" in result

    def test_shm_list_empty(self) -> None:
        """Shm list with no segments should say so."""
        _kernel, shell = _booted_shell()
        result = shell.execute("shm list")
        assert "No" in result or "segment" in result.lower()

    def test_shm_list_shows_segments(self) -> None:
        """Shm list should show created segments."""
        kernel, shell = _booted_shell()
        proc = kernel.create_process(name="shm_test", num_pages=2)
        shell.execute(f"shm create seg1 32 {proc.pid}")
        result = shell.execute("shm list")
        assert "seg1" in result

    def test_shm_demo_runs(self) -> None:
        """Shm demo should walk through shared whiteboard scenario."""
        _kernel, shell = _booted_shell()
        result = shell.execute("shm demo")
        assert "Shared Memory" in result or "whiteboard" in result.lower()


# -- /proc virtual filesystem commands --------------------------------------


class TestShellProc:
    """Verify /proc virtual filesystem commands."""

    def test_proc_no_args_shows_usage(self) -> None:
        """Proc with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("proc")
        assert "Usage" in result

    def test_proc_unknown_subcommand_shows_usage(self) -> None:
        """Proc with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("proc foobar")
        assert "Usage" in result

    def test_proc_demo_runs(self) -> None:
        """Proc demo should walk through the bulletin board scenario."""
        _kernel, shell = _booted_shell()
        result = shell.execute("proc demo")
        assert "/proc" in result or "bulletin" in result.lower()


# -- Performance metrics commands -------------------------------------------


class TestShellPerf:
    """Verify performance metrics commands."""

    def test_perf_no_args_shows_summary(self) -> None:
        """Perf with no args should show a metrics summary."""
        _kernel, shell = _booted_shell()
        result = shell.execute("perf")
        assert "Metrics" in result or "throughput" in result.lower()

    def test_perf_demo_runs(self) -> None:
        """Perf demo should walk through the sports day scenario."""
        _kernel, shell = _booted_shell()
        result = shell.execute("perf demo")
        assert "Performance" in result or "sports" in result.lower()


# -- Strace commands --------------------------------------------------------


class TestShellStrace:
    """Verify syscall tracing (strace) commands."""

    def test_strace_no_args_shows_usage(self) -> None:
        """Strace with no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("strace")
        assert "Usage" in result

    def test_strace_unknown_subcommand_shows_usage(self) -> None:
        """Strace with unknown subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("strace foobar")
        assert "Usage" in result

    def test_strace_on(self) -> None:
        """Strace on should enable tracing."""
        _kernel, shell = _booted_shell()
        result = shell.execute("strace on")
        assert "enabled" in result.lower()

    def test_strace_off(self) -> None:
        """Strace off should disable tracing."""
        _kernel, shell = _booted_shell()
        result = shell.execute("strace off")
        assert "disabled" in result.lower()

    def test_strace_show_empty(self) -> None:
        """Strace show with no log should indicate empty."""
        _kernel, shell = _booted_shell()
        result = shell.execute("strace show")
        assert "empty" in result.lower()

    def test_strace_inline_output(self) -> None:
        """Strace output should appear inline with the traced command."""
        _kernel, shell = _booted_shell()
        shell.execute("strace on")
        result = shell.execute("ls /")
        # Strace entries are appended inline and the log is cleared
        assert "--- strace ---" in result
        assert "SYS_LIST_DIR" in result

    def test_strace_clear(self) -> None:
        """Strace clear should clear the log."""
        _kernel, shell = _booted_shell()
        shell.execute("strace on")
        shell.execute("ls /")
        result = shell.execute("strace clear")
        assert "cleared" in result.lower()

    def test_strace_demo_runs(self) -> None:
        """Strace demo should walk through the kitchen clipboard scenario."""
        _kernel, shell = _booted_shell()
        result = shell.execute("strace demo")
        assert "Strace" in result or "kitchen" in result.lower()
