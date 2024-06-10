"""A simple HTTP server built directly on top of socket.socket."""
from socketwrench.standardlib_dependencies import (
    logging,
    Path,
    socket,
    sleep,
    threading_available
)

from socketwrench.connection import Connection
from socketwrench.handlers import RouteHandler, wrap_handler, is_object_instance

logger = logging.getLogger("socketwrench")


class Server(socket.socket):
    """A simple HTTP server built directly on top of socket.socket."""
    default_port = 8080
    default_host = ''
    default_backlog = 1
    default_chunk_size = Connection.default_chunk_size
    default_num_connection_threads = None
    default_socket_options = {
        socket.SOL_SOCKET: {
            socket.SO_REUSEADDR: 1
        }
    }
    default_pause_sleep = 0.1
    default_accept_sleep = 0
    default_favicon = RouteHandler.default_favicon

    def __init__(self,
                 routes: dict = None,
                 port: int = default_port,
                 host: str = default_host,
                 backlog: int = default_backlog,
                 chunk_size: int = default_chunk_size,
                 num_connection_threads: int = default_num_connection_threads,
                 socket_options: dict = "default",
                 pause_sleep: float = default_pause_sleep,
                 accept_sleep: float = default_accept_sleep,
                 fallback_handler=None,
                 serve: bool = True,
                 favicon: str = default_favicon,
                 protocol: str = "http",
                 secured: bool = False,
                 origin: str = None,
                 **kwargs
                 ):
        """A simple HTTP server built directly on top of socket.socket.

        Args:
            routes (dict[str, RequestHandler] | None, optional): A dictionary of routes to handlers.
            port (int, optional): The port to listen on. Defaults to 8080.
            host (str, optional): The host to listen on. Defaults to ''.
            backlog (int, optional): The maximum number of queued connections. Defaults to 1.
            chunk_size (int, optional): The default chunk size to use when receiving data. Defaults to 1024.
            num_connection_threads (int, optional): The number of threads to use for handling connections. Defaults to 1.
            socket_options (dict[int, dict[int, int]] | None, optional): A dictionary of socket options to set on the server socket.
                The keys are the levels, and the values are dictionaries of options and values. Defaults to None.
                e.g. {socket.SOL_SOCKET: {socket.SO_REUSEADDR: 1}}
            pause_sleep (float, optional): The number of seconds to sleep between checking the threading.Event
                when the server is paused. Could affect CPU and latency. Defaults to 0.1.
            accept_sleep (float, optional): The number of seconds to sleep between checking for new connections.
                Could affect latency. Defaults to 0.1.
            fallback_handler (RequestHandler, optional): The function to use to handle requests that don't match any routes.
            serve (bool, optional): Whether to start serving immediately. Defaults to True.
            favicon (str, optional): The path to the favicon to use. Defaults to None.
            protocol (str, optional): The protocol to use for the server in logging statements. Defaults to "http".
            secured (bool, optional): Whether the server is secured. Defaults to False. Only used for logging full url.
            origin (str, optional): The full URL to use for the server in logging statements, otherwise we guess. Defaults to None.
        """
        if socket_options == "default":
            socket_options = self.default_socket_options
        if isinstance(routes, type):
            routes = routes()

        s = str(routes)
        s2 = s.split("\n")[0][:50]
        s = s2 + ("..." if len(s) > len(s2) else "")
        logger.info(f"Creating server with {s}")

        if callable(routes) and not is_object_instance(routes):
            if isinstance(routes, RouteHandler):
                self.handler = routes
            else:
                self.handler = wrap_handler(routes)
        else:
            self.handler = RouteHandler(
                fallback_handler=fallback_handler,
                routes=routes,
                base_path="/",
                favicon=favicon,
                **kwargs
            )

        self.host = host
        self.port = port

        if origin is None:
            if secured and protocol.lower() == "http":
                protocol = "https"
            else:
                protocol = protocol.lower()
            if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
                p = ""
            else:
                p = f":{port}"
            origin = f"{protocol}://{host or 'localhost'}{p}"
        self.origin = origin
        self.backlog = backlog
        self.chunk_size = chunk_size
        self.num_connection_threads = num_connection_threads
        self.pause_sleep = pause_sleep
        self.accept_sleep = accept_sleep
        self.init_socket_options = socket_options
        self.thread_pool_executor = None
        self.server_thread = None
        self.cleanup_event = None
        self.pause_event = None

        self._rep = None

        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.set_socket_options(socket_options or {})

        if serve:
            if serve == "thread":
                self.serve(thread=True)
            else:
                self.serve()

    def set_socket_options(self, socket_options: dict[int, dict[int, int]]) -> None:
        """Sets the socket options on the server socket.

        Args:
            socket_options (dict[int, dict[int, int]]): A dictionary of socket options to set on the server socket.
                The keys are the levels, and the values are dictionaries of options and values.
                e.g. {socket.SOL_SOCKET: {socket.SO_REUSEADDR: 1}}
        """
        if not socket_options:
            return

        # set socket options
        for level, options in socket_options.items():
            for option, value in options.items():
                self.setsockopt(level, option, value)

    def serve(self, thread: int = False, run_in_background=False, cleanup_event = None, pause_event = None, nav_path="/", **kwargs) -> tuple:
        if not isinstance(self, Server):
            if isinstance(self, str) or "<module" in str(type(self)):
                return Server.serve_module(self, thread=thread, run_in_background=run_in_background,
                                           cleanup_event=cleanup_event, pause_event=pause_event, nav_path=nav_path, **kwargs)
            elif isinstance(self, type):
                return Server.serve_class(self, thread=thread, run_in_background=run_in_background,
                                          cleanup_event=cleanup_event, pause_event=pause_event, nav_path=nav_path,**kwargs)
            # allows classmethod-like usage of Server.serve(my_server_instance)
            return Server(self, nav_path=nav_path, serve=False, **kwargs).serve(thread=thread, run_in_background=run_in_background,
                            cleanup_event=cleanup_event, pause_event=pause_event)
        if thread:
            if threading_available:
                from socketwrench.standardlib_dependencies import ThreadPoolExecutor
                from concurrent.futures import ThreadPoolExecutor
                self.thread_pool_executor = ThreadPoolExecutor(max_workers=self.num_connection_threads)
                logger.info(f"Using ThreadPoolExecutor with max_workers={self.num_connection_threads}.")
            else:
                raise RuntimeError("Threading is not available on this platform.")

        if run_in_background:
            if threading_available:
                from socketwrench.standardlib_dependencies import Event, Thread

                self.cleanup_event = Event()
                self.pause_event = Event()

                logger.info("Starting server in background thread. Make sure to keep the main thread alive.")
                t = Thread(target=self.serve, args=(False, self.cleanup_event, self.pause_event), daemon=True)
                t.start()
                self.server_thread = t
                return t, self.cleanup_event, self.pause_event
            else:
                raise RuntimeError("Threading is not available on this platform.")


        self.bind((self.host, self.port))
        self.listen(self.backlog)
        self.settimeout(1) # timeout for accept, allows Keyboard Interrupt to shutdown the server
        logger.info("Serving HTTP on port " + str(self.port) + "...")
        logger.info(f"Press Ctrl+C to stop the server.")
        logger.info(f"Go to {self.origin}/swagger to see documentation.")
        logger.info(f"Go to {self.origin}/api for an api playground.")

        while cleanup_event is None or (not cleanup_event.is_set()):
            if self.pause_sleep and pause_event is not None:
                while pause_event.is_set() and (cleanup_event is None or (not cleanup_event.is_set())):
                    sleep(self.pause_sleep)
            if self.accept_sleep:
                sleep(self.accept_sleep)
            try:
                connection = self.accept_connection()

                # handle connection
                if self.thread_pool_executor:
                    self.thread_pool_executor.submit(connection.handle)
                else:
                    connection.handle()
            except socket.timeout:
                pass

    def accept_connection(self) -> Connection:
        """Accepts a connection and returns a Connection object."""
        client_connection, client_address = self.accept()
        connection = self.make_connection(client_connection, client_address)
        return connection

    def make_connection(self, client_connection, client_address) -> Connection:
        """Makes a connection and returns a Connection object."""
        connection = Connection(self.handler, client_connection, client_address,
                                cleanup_event=self.cleanup_event,
                                chunk_size=self.chunk_size,
                                origin=self.origin)
        return connection

    def close(self) -> None:
        """Closes the server socket."""
        if self.server_thread:
            self.cleanup_event.set()
            self.server_thread.join()
        super().close()

    def __repr__(self) -> str:
        if self._rep is None:
            r = f"<{self.__class__.__name__}("
            if self.port != self.default_port:
                r += f"port={self.port}, "
            if self.host != self.default_host:
                r += f"host={self.host}, "
            if self.backlog != self.default_backlog:
                r += f"backlog={self.backlog}, "
            if self.chunk_size != self.default_chunk_size:
                r += f"chunk_size={self.chunk_size}, "
            if self.num_connection_threads != self.default_num_connection_threads:
                r += f"num_connection_threads={self.num_connection_threads}, "
            if self.init_socket_options != self.default_socket_options:
                r += f"init_socket_options={self.init_socket_options}, "
            if self.pause_sleep != self.default_pause_sleep:
                r += f"pause_sleep={self.pause_sleep}, "
            if self.accept_sleep != self.default_accept_sleep:
                r += f"accept_sleep={self.accept_sleep}, "
            r = r.rstrip(", ")
            r += ")>"
            self._rep = r
        return self._rep


    @classmethod
    def serve_class(cls, c, thread: bool = False, cleanup_event = None, pause_event = None, run_in_background=False, **kwargs):
        inst = c()
        return cls(inst, serve=False, **kwargs).serve(thread=thread, cleanup_event=cleanup_event, pause_event=pause_event, run_in_background=run_in_background)

    @classmethod
    def serve_module(cls, module, thread: bool = False, cleanup_event = None, pause_event = None, run_in_background=False, **kwargs):
        if isinstance(module, Path):
            from socketwrench.standardlib_dependencies import importlib, modules
            module = importlib.util.spec_from_file_location("module", module)
            module = importlib.util.module_from_spec(module)
            module.__file__ = module.__spec__.origin
            module.__package__ = module.__spec__.name
            modules[module.__spec__.name] = module
            module.__spec__.loader.exec_module(module)
        elif isinstance(module, str):
            try:
                from socketwrench.standardlib_dependencies import importlib
                module = importlib.import_module(module)
            except ImportError:
                parts = module.split(".")
                module = importlib.import_module(".".join(parts[:-1]))
                module = getattr(module, parts[-1])
        return cls(module, **kwargs).serve(thread=thread, cleanup_event=cleanup_event, pause_event=pause_event, run_in_background=run_in_background)

