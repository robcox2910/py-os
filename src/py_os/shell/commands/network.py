"""Networking commands -- DNS, sockets, TCP and HTTP."""

import contextlib
from collections.abc import Callable

from py_os.io.http import (
    HttpMethod,
    HttpRequest,
    HttpResponse,
    HttpStatus,
    format_request,
    format_response,
    parse_request,
    parse_response,
    status_reason,
)
from py_os.io.networking import SocketManager
from py_os.shell.base import ShellBase
from py_os.syscalls import SyscallError, SyscallNumber

# A table of sub-commands: word typed by the user -> the method that handles it.
type _SubcommandTable = dict[str, Callable[[list[str]], str]]

_NEVER_ACCEPTED = "the server never accepted the connection"


class NetworkCommands(ShellBase):
    """Shell commands for DNS, sockets, TCP and HTTP."""

    def _cmd_dns(self, args: list[str]) -> str:
        """Manage DNS records — the phone book for hostname → IP resolution."""
        dispatch: _SubcommandTable = {
            "register": self._cmd_dns_register,
            "lookup": self._cmd_dns_lookup,
            "remove": self._cmd_dns_remove,
            "list": lambda _a: self._cmd_dns_list(),
            "flush": lambda _a: self._cmd_dns_flush(),
            "demo": lambda _a: self._cmd_dns_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: dns <register|lookup|remove|list|flush|demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_dns_register(self, args: list[str]) -> str:
        """Register a DNS A record."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: dns register <hostname> <ip>"
        hostname = args[0]
        address = args[1]
        try:
            result: dict[str, str] = self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER, hostname=hostname, address=address
            )
            return f"Registered {result['hostname']} -> {result['address']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_dns_lookup(self, args: list[str]) -> str:
        """Look up a hostname."""
        if not args:
            return "Usage: dns lookup <hostname>"
        hostname = args[0]
        try:
            address: str = self._kernel.syscall(SyscallNumber.SYS_DNS_LOOKUP, hostname=hostname)
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"{hostname} -> {address}"

    def _cmd_dns_remove(self, args: list[str]) -> str:
        """Remove a DNS record."""
        if not args:
            return "Usage: dns remove <hostname>"
        hostname = args[0]
        try:
            self._kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname=hostname)
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"Removed {hostname}"

    def _cmd_dns_list(self) -> str:
        """List all DNS records."""
        records: list[dict[str, str]] = self._kernel.syscall(SyscallNumber.SYS_DNS_LIST)
        if not records:
            return "No DNS records."
        lines = ["HOSTNAME                 ADDRESS"]
        lines.extend(f"{rec['hostname']:<24} {rec['address']}" for rec in records)
        return "\n".join(lines)

    def _cmd_dns_flush(self) -> str:
        """Flush all DNS records."""
        count: int = self._kernel.syscall(SyscallNumber.SYS_DNS_FLUSH)
        return f"Flushed {count} DNS records"

    def _cmd_dns_demo(self) -> str:
        """Walk through a DNS demo — name resolution over sockets."""
        lines: list[str] = [
            "=== DNS Demo: Name Resolution Over Sockets ===",
            "",
            "DNS is like a phone book. You know your friend's name",
            "but not their phone number. You open the phone book,",
            "look up the name, and find the number.",
            "",
        ]

        demo_host_1 = "_demo.example.com"
        demo_ip_1 = "93.184.216.34"
        demo_host_2 = "_demo.pyos.local"
        demo_ip_2 = "10.0.0.42"
        dns_port = 53

        try:
            # Step 1: Register demo records
            self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname=demo_host_1,
                address=demo_ip_1,
            )
            self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname=demo_host_2,
                address=demo_ip_2,
            )
            lines.append(
                f"Step 1: Register demo records:"
                f"\n  {demo_host_1} -> {demo_ip_1}"
                f"\n  {demo_host_2} -> {demo_ip_2}"
            )
            lines.append("")

            # Step 2: Set up sockets (used directly — not kernel-integrated yet)
            sm = SocketManager()
            server = sm.create_socket()
            server.bind(address="localhost", port=dns_port)
            server.listen()
            lines.append(f"Step 2: DNS server socket bound to localhost:{dns_port}, listening")

            # Step 3: Client connects
            client = sm.create_socket()
            sm.connect(client, address="localhost", port=dns_port)
            peer = sm.accept(server)
            if peer is None:
                raise RuntimeError(_NEVER_ACCEPTED)
            lines.append("Step 3: Client connects to the DNS server")
            lines.append("")

            # Step 4: Client sends a query
            query = f"QUERY A {demo_host_1}"
            sm.send(client, query.encode())
            lines.append(f'Step 4: Client sends: "{query}"')

            # Step 5: Server receives and resolves
            raw = sm.recv(peer)
            query_text = raw.decode()
            parts = query_text.split()
            queried_host = parts[2]
            resolved_ip: str = self._kernel.syscall(
                SyscallNumber.SYS_DNS_LOOKUP, hostname=queried_host
            )
            answer = f"ANSWER {queried_host} {resolved_ip}"
            sm.send(peer, answer.encode())
            lines.append(
                f"Step 5: Server receives query, looks up '{queried_host}',"
                f'\n  resolves to {resolved_ip}, sends: "{answer}"'
            )

            # Step 6: Client receives the answer
            response = sm.recv(client).decode()
            lines.append(f'Step 6: Client receives: "{response}"')
            lines.append("")

            # Teaching summary
            lines.append("How it works:")
            lines.append("  - DNS queries travel over sockets (real DNS uses port 53)")
            lines.append("  - The query/answer is just text (real DNS uses a binary format)")
            lines.append("  - This is protocol layering: DNS runs ON TOP of sockets")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            # Clean up demo records
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname=demo_host_1)
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname=demo_host_2)

        return "\n".join(lines)

    def _cmd_socket(self, args: list[str]) -> str:
        """Manage raw sockets — create, bind, listen, connect, accept, send, recv, close, list."""
        dispatch: _SubcommandTable = {
            "create": lambda _a: self._cmd_socket_create(),
            "bind": self._cmd_socket_bind,
            "listen": self._cmd_socket_listen,
            "connect": self._cmd_socket_connect,
            "accept": self._cmd_socket_accept,
            "send": self._cmd_socket_send,
            "recv": self._cmd_socket_recv,
            "close": self._cmd_socket_close,
            "list": lambda _a: self._cmd_socket_list(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: socket <create|bind|listen|connect|accept|send|recv|close|list>"
        return dispatch[args[0]](args[1:])

    def _cmd_socket_create(self) -> str:
        """Create a new socket."""
        try:
            result: dict[str, int | str] = self._kernel.syscall(SyscallNumber.SYS_SOCKET_CREATE)
            return f"Socket {result['sock_id']} created (state: {result['state']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_bind(self, args: list[str]) -> str:
        """Bind a socket to an address and port."""
        expected_args = 3
        if len(args) < expected_args:
            return "Usage: socket bind <id> <address> <port>"
        try:
            sock_id = int(args[0])
            port = int(args[2])
        except ValueError:
            return "Error: id and port must be integers"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_BIND, sock_id=sock_id, address=args[1], port=port
            )
            return f"Socket {sock_id} bound to {args[1]}:{port}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_listen(self, args: list[str]) -> str:
        """Mark a socket as listening."""
        if not args:
            return "Usage: socket listen <id>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_LISTEN, sock_id=sock_id)
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"Socket {sock_id} listening"

    def _cmd_socket_connect(self, args: list[str]) -> str:
        """Connect a socket to a listener."""
        expected_args = 3
        if len(args) < expected_args:
            return "Usage: socket connect <id> <address> <port>"
        try:
            sock_id = int(args[0])
            port = int(args[2])
        except ValueError:
            return "Error: id and port must be integers"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_CONNECT, sock_id=sock_id, address=args[1], port=port
            )
            return f"Socket {sock_id} connected to {args[1]}:{port}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_accept(self, args: list[str]) -> str:
        """Accept a pending connection."""
        if not args:
            return "Usage: socket accept <id>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_SOCKET_ACCEPT, sock_id=sock_id)
            if result is None:
                return "No pending connections"
            return f"Accepted connection: peer socket {result['sock_id']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_send(self, args: list[str]) -> str:
        """Send data over a socket."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: socket send <id> <data>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        data = " ".join(args[1:])
        try:
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_SEND, sock_id=sock_id, data=data.encode())
            return f"Sent {len(data)} bytes on socket {sock_id}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_recv(self, args: list[str]) -> str:
        """Receive data from a socket."""
        if not args:
            return "Usage: socket recv <id>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_SOCKET_RECV, sock_id=sock_id)
            if not data:
                return "(no data)"
            return data.decode(errors="replace")
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_close(self, args: list[str]) -> str:
        """Close a socket."""
        if not args:
            return "Usage: socket close <id>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_CLOSE, sock_id=sock_id)
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"Socket {sock_id} closed"

    def _cmd_socket_list(self) -> str:
        """List all sockets."""
        sockets: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_SOCKET_LIST)
        if not sockets:
            return "No sockets."
        lines = ["ID     STATE        ADDRESS          PORT"]
        for s in sockets:
            sid = s["sock_id"]
            state = s["state"]
            addr = s.get("address") or "-"
            port = s.get("port") or "-"
            lines.append(f"{sid:<6} {state:<12} {addr:<16} {port}")
        return "\n".join(lines)

    def _cmd_http(self, args: list[str]) -> str:
        """HTTP protocol demo — request/response over sockets."""
        dispatch: _SubcommandTable = {
            "demo": lambda _a: self._cmd_http_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: http <demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_http_demo(self) -> str:  # noqa: PLR0915
        """Walk through an HTTP demo — serve a file over sockets."""
        lines: list[str] = [
            "=== HTTP Demo: Request/Response Over Sockets ===",
            "",
            "HTTP is like a restaurant. The customer (client) fills out an",
            "order form (request), the waiter (socket) carries it to the",
            "kitchen (server), and the kitchen sends back a receipt (response).",
            "",
        ]

        demo_host = "_demo.webserver"
        demo_ip = "10.0.0.80"
        demo_port = 80
        demo_path = "/www/index.html"
        demo_content = "<h1>Welcome to PyOS!</h1>"
        missing_path = "/www/missing.html"

        # Track socket IDs for cleanup
        sock_ids: list[int] = []

        try:
            # Step 1: Create file in filesystem
            self._kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/www")
            self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path=demo_path)
            self._kernel.syscall(
                SyscallNumber.SYS_WRITE_FILE,
                path=demo_path,
                data=demo_content.encode(),
            )
            lines.append(f'Step 1: Created {demo_path} with "{demo_content}"')
            lines.append("")

            # Step 2: Register DNS
            self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname=demo_host,
                address=demo_ip,
            )
            lines.append(f"Step 2: Registered DNS: {demo_host} -> {demo_ip}")
            lines.append("")

            # Step 3: Server socket — create, bind, listen (via syscalls)
            srv = self._kernel.syscall(SyscallNumber.SYS_SOCKET_CREATE)
            srv_id = srv["sock_id"]
            sock_ids.append(srv_id)
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_BIND,
                sock_id=srv_id,
                address=demo_ip,
                port=demo_port,
            )
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_LISTEN, sock_id=srv_id)
            lines.append(f"Step 3: Server socket {srv_id} listening on {demo_ip}:{demo_port}")

            # Step 4: Client socket — create and connect
            cli = self._kernel.syscall(SyscallNumber.SYS_SOCKET_CREATE)
            cli_id = cli["sock_id"]
            sock_ids.append(cli_id)
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_CONNECT,
                sock_id=cli_id,
                address=demo_ip,
                port=demo_port,
            )
            lines.append(f"Step 4: Client socket {cli_id} connected to {demo_ip}:{demo_port}")
            lines.append("")

            # Step 5: Server accepts
            peer = self._kernel.syscall(SyscallNumber.SYS_SOCKET_ACCEPT, sock_id=srv_id)
            if peer is None:
                raise RuntimeError(_NEVER_ACCEPTED)
            peer_id = peer["sock_id"]
            sock_ids.append(peer_id)
            lines.append(f"Step 5: Server accepted connection (peer socket {peer_id})")
            lines.append("")

            # Step 6: Client sends HTTP GET request
            request = HttpRequest(
                method=HttpMethod.GET,
                path=demo_path,
                headers={"Host": demo_host},
            )
            request_bytes = format_request(request)
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND,
                sock_id=cli_id,
                data=request_bytes,
            )
            lines.append(f"Step 6: Client sends: GET {demo_path} HTTP/1.0")

            # Step 7: Server receives and parses
            raw_request: bytes = self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_RECV, sock_id=peer_id
            )
            parsed = parse_request(raw_request)
            lines.append(f"Step 7: Server receives request: {parsed.method} {parsed.path}")

            # Step 8: Server reads file and builds response
            file_data: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=parsed.path)
            response = HttpResponse(
                status=HttpStatus.OK,
                headers={"Content-Type": "text/html"},
                body=file_data,
            )
            response_bytes = format_response(response)
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND,
                sock_id=peer_id,
                data=response_bytes,
            )
            lines.append(
                f"Step 8: Server reads file, sends: HTTP/1.0 {response.status}"
                f" {status_reason(response.status)}"
            )
            lines.append("")

            # Step 9: Client receives and parses response
            raw_response: bytes = self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_RECV, sock_id=cli_id
            )
            parsed_resp = parse_response(raw_response)
            lines.append(
                f"Step 9: Client receives: {parsed_resp.status} {status_reason(parsed_resp.status)}"
            )
            lines.append(f"  Body: {parsed_resp.body.decode()}")
            lines.append("")

            # Step 10: Show 404 — request a missing file
            lines.append("--- Now requesting a file that doesn't exist ---")
            lines.append("")
            request_404 = HttpRequest(
                method=HttpMethod.GET,
                path=missing_path,
                headers={"Host": demo_host},
            )
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND,
                sock_id=cli_id,
                data=format_request(request_404),
            )
            raw_404: bytes = self._kernel.syscall(SyscallNumber.SYS_SOCKET_RECV, sock_id=peer_id)
            parsed_404 = parse_request(raw_404)

            # Server tries to read the file — it won't exist
            try:
                self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=parsed_404.path)
                # If we somehow get here, send 200 (shouldn't happen)
                resp_404 = HttpResponse(status=HttpStatus.OK, headers={})
            except SyscallError:
                resp_404 = HttpResponse(
                    status=HttpStatus.NOT_FOUND,
                    headers={},
                    body=b"404 Not Found",
                )

            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND,
                sock_id=peer_id,
                data=format_response(resp_404),
            )
            raw_404_resp: bytes = self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_RECV, sock_id=cli_id
            )
            parsed_404_resp = parse_response(raw_404_resp)
            lines.append(
                f"Step 10: GET {missing_path} -> {parsed_404_resp.status}"
                f" {status_reason(parsed_404_resp.status)}"
            )
            lines.append(f"  Body: {parsed_404_resp.body.decode()}")
            lines.append("")

            # Teaching summary
            lines.append("How it works:")
            lines.append("  - HTTP is a request/response protocol (client asks, server answers)")
            lines.append("  - Requests have a method (GET, POST) and a path (/index.html)")
            lines.append("  - Responses have a status code (200 OK, 404 Not Found)")
            lines.append("  - HTTP runs ON TOP of sockets — protocol layering!")
            lines.append("  - All socket operations go through syscalls (kernel integration)")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            # Clean up: close sockets, remove DNS, delete files
            for sid in sock_ids:
                with contextlib.suppress(SyscallError):
                    self._kernel.syscall(SyscallNumber.SYS_SOCKET_CLOSE, sock_id=sid)
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname=demo_host)
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path=demo_path)
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/www")

        return "\n".join(lines)

    def _cmd_tcp(self, args: list[str]) -> str:
        """Manage TCP connections — listen, connect, send, recv, close, info, list, demo."""
        dispatch: _SubcommandTable = {
            "listen": self._cmd_tcp_listen,
            "connect": self._cmd_tcp_connect,
            "send": self._cmd_tcp_send,
            "recv": self._cmd_tcp_recv,
            "close": self._cmd_tcp_close,
            "info": self._cmd_tcp_info,
            "list": lambda _a: self._cmd_tcp_list(),
            "demo": lambda _a: self._cmd_tcp_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: tcp <listen|connect|send|recv|close|info|list|demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_tcp_listen(self, args: list[str]) -> str:
        """Start listening on a TCP port."""
        if not args:
            return "Usage: tcp listen <port>"
        try:
            port = int(args[0])
        except ValueError:
            return "Error: port must be an integer"
        try:
            listener_id: int = self._kernel.syscall(SyscallNumber.SYS_TCP_LISTEN, port=port)
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"Listening on port {port} (listener_id={listener_id})"

    def _cmd_tcp_connect(self, args: list[str]) -> str:
        """Open a TCP connection."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: tcp connect <client_port> <server_port>"
        try:
            client_port = int(args[0])
            server_port = int(args[1])
        except ValueError:
            return "Error: ports must be integers"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_TCP_CONNECT,
                client_port=client_port,
                server_port=server_port,
            )
            return f"Connection {result['conn_id']} opened (state: {result['state']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_tcp_send(self, args: list[str]) -> str:
        """Send data over a TCP connection."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: tcp send <conn_id> <data>"
        try:
            conn_id = int(args[0])
        except ValueError:
            return "Error: conn_id must be an integer"
        data = " ".join(args[1:])
        try:
            sent: int = self._kernel.syscall(
                SyscallNumber.SYS_TCP_SEND, conn_id=conn_id, data=data.encode()
            )
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"Sent {sent} bytes on connection {conn_id}"

    def _cmd_tcp_recv(self, args: list[str]) -> str:
        """Receive data from a TCP connection."""
        if not args:
            return "Usage: tcp recv <conn_id>"
        try:
            conn_id = int(args[0])
        except ValueError:
            return "Error: conn_id must be an integer"
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_TCP_RECV, conn_id=conn_id)
            if not data:
                return "(no data)"
            return data.decode(errors="replace")
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_tcp_close(self, args: list[str]) -> str:
        """Close a TCP connection."""
        if not args:
            return "Usage: tcp close <conn_id>"
        try:
            conn_id = int(args[0])
        except ValueError:
            return "Error: conn_id must be an integer"
        try:
            self._kernel.syscall(SyscallNumber.SYS_TCP_CLOSE, conn_id=conn_id)
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"Connection {conn_id} closed"

    def _cmd_tcp_info(self, args: list[str]) -> str:
        """Show TCP connection info."""
        if not args:
            return "Usage: tcp info <conn_id>"
        try:
            conn_id = int(args[0])
        except ValueError:
            return "Error: conn_id must be an integer"
        try:
            info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_TCP_INFO, conn_id=conn_id
            )
            lines = [f"TCP Connection {conn_id}:"]
            for key, val in info.items():
                lines.append(f"  {key}: {val}")
            return "\n".join(lines)
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_tcp_list(self) -> str:
        """List all TCP connections."""
        try:
            conns: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_TCP_LIST)
        except SyscallError as e:
            return f"Error: {e}"
        if not conns:
            return "No TCP connections."
        lines = ["ID     STATE            LOCAL    REMOTE"]
        for c in conns:
            cid = c.get("conn_id", "?")
            state = c.get("state", "?")
            local = c.get("local_port", "-")
            remote = c.get("remote_port", "-")
            lines.append(f"{cid:<6} {state!s:<16} {local!s:<8} {remote}")
        return "\n".join(lines)

    def _cmd_tcp_demo(self) -> str:
        """Run a complete TCP demo: listen, connect, handshake, send/recv, close."""
        lines: list[str] = ["=== TCP Demo ===", ""]

        # Step 1: Listen
        lines.append("1. Start a listener on port 8080")
        try:
            listener_id: int = self._kernel.syscall(SyscallNumber.SYS_TCP_LISTEN, port=8080)
            lines.append(f"   Listener ready (id={listener_id})")
        except SyscallError as e:
            return "\n".join([*lines, f"   Error: {e}"])
        lines.append("")

        # Step 2: Connect (triggers three-way handshake)
        lines.append("2. Client connects from port 5000 to port 8080")
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_TCP_CONNECT,
                client_port=5000,
                server_port=8080,
            )
            client_id = int(str(result["conn_id"]))
            lines.append(f"   Client connection {client_id} (state: {result['state']})")
        except SyscallError as e:
            return "\n".join([*lines, f"   Error: {e}"])

        # Accept the server side
        try:
            server_id: int | None = self._kernel.syscall(
                SyscallNumber.SYS_TCP_ACCEPT, listener_id=listener_id
            )
            lines.append(f"   Server accepted (conn_id={server_id})")
        except SyscallError as e:
            return "\n".join([*lines, f"   Error: {e}"])
        lines.append("")

        # Step 3: Send and receive data
        lines.append("3. Send data: 'Hello, TCP!'")
        try:
            sent: int = self._kernel.syscall(
                SyscallNumber.SYS_TCP_SEND,
                conn_id=client_id,
                data=b"Hello, TCP!",
            )
            lines.append(f"   Sent {sent} bytes")
            if server_id is not None:
                data: bytes = self._kernel.syscall(SyscallNumber.SYS_TCP_RECV, conn_id=server_id)
                lines.append(f"   Server received: '{data.decode()}'")
        except SyscallError as e:
            lines.append(f"   Error: {e}")
        lines.append("")

        # Step 4: Show congestion info
        lines.append("4. Connection info (congestion window, etc.)")
        try:
            info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_TCP_INFO, conn_id=client_id
            )
            lines.append(f"   cwnd={info['cwnd']}, ssthresh={info['ssthresh']}")
        except SyscallError as e:
            lines.append(f"   Error: {e}")
        lines.append("")

        # Step 5: Close
        lines.append("5. Close both connections")
        for cid in (client_id, server_id, listener_id):
            if cid is not None:
                with contextlib.suppress(SyscallError):
                    self._kernel.syscall(SyscallNumber.SYS_TCP_CLOSE, conn_id=cid)
        lines.append("   Connections closed.")

        return "\n".join(lines)

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("dns", _cmd_dns),
        ("socket", _cmd_socket),
        ("http", _cmd_http),
        ("tcp", _cmd_tcp),
    )
