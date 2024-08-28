import threading
import builtins

from socketwrench.standardlib_dependencies import (
    logging,
    socket,
)
from multiprocessing import Queue
from socketwrench.types import Request, Response, InternalServerError, BadRequest, RedirectResponse, HTTPStatusCode

logger = logging.getLogger("socketwrench")


class NewInput:
    pending_inputs = {}

    def __init__(self, prompt, path, connection_id, timeout=30):
        self.id = connection_id
        self.prompt = prompt
        self.path = path
        self.timeout = timeout
        self.client_input_queue = Queue()
        self.server_result_queue = Queue()
        self.result = None
        NewInput.pending_inputs[self.id] = self

    def to_dict(self):
        return {
            "id": self.id,
            "prompt": self.prompt,
            "connection_id": self.connection_id,
            "timeout": self.timeout,
            "result": self.result,
        }

    @classmethod
    def from_dict(cls, d):
        id = d["id"]
        return cls.pending_inputs.get(id)

    def wait_for_input(self):
        r = self.client_input_queue.get(timeout=self.timeout)
        if isinstance(r, dict) and len(r) == 1 and "new_input" in r:
            new_id = r["new_input"]
            new_input = NewInput.pending_inputs.get(new_id)
            r = new_input.wait_for_input()
        self.result = r
        return self.result

    def get_html(self):
        return f"""<html>
<head>
</head>
<body>
    <pre>{self.prompt}</pre>
</body>
<script>
    var input = prompt(`{self.prompt}`);
    location.href = location.href + `&socketwrench_input_value=${{encodeURIComponent(input)}}`;
</script> 
</html>"""

    def redirect_to_get_input(self):
        p = self.path
        if "?" in p:
            p += "&"
        else:
            p += "?"
        return RedirectResponse(p + f"socketwrench_input_id={self.id}")

    def prompt_for_input(self):
        p = self.path
        if "?" in p:
            p += "&"
        else:
            p += "?"
        return Response(self.get_html(),
                        status_code=HTTPStatusCode.PAYMENT_REQUIRED,
                        headers={"Content-Type": "text/html",
                                 "x-prompt": self.prompt,
                                 "x-input-id": str(self.id),
                        })


class Connection:
    default_chunk_size: int = 1024
    timeout = 5
    thread_connections = {}

    @staticmethod
    def custom_input(prompt=""):
        call_id = hex(threading.get_ident())[2:]
        i = NewInput.pending_inputs.get(call_id, None)
        if i is not None:
            # we are reusing this prompt, meaning we have already responded to this connection,
            # so we need to put the next redirect into the queue the next request is looking at
            i.prompt = prompt
            r = i.redirect_to_get_input()
            i.server_result_queue.put(r)
        else:
            # we are creating a new prompt, so we need to redirect the user to the new prompt
            c = Connection.thread_connections[call_id]
            i = NewInput(prompt, path=c.path, connection_id=call_id)
            r = i.redirect_to_get_input()
            c.send_response(c.socket, r)
        r = i.wait_for_input()
        if isinstance(r, dict) and len(r) == 1 and "socketwrench_input_exit" in r:
            raise Exception("User exited input prompt.")
        return r

    def __init__(self,
                 handler,
                 connection_socket: socket.socket,
                 client_address: tuple,
                 cleanup_event,
                 chunk_size: int = default_chunk_size,
                 origin: str = ""):
        self.socket = connection_socket
        self.client_addr = client_address
        self.chunk_size = chunk_size
        self.cleanup_event = cleanup_event
        self.handler = handler
        self.origin = origin
        self.path = None

        self._rep = None

    def handle(self):
        socket = self.socket
        # use random to get a random hex 16
        call_id = hex(threading.get_ident())[2:]
        Connection.thread_connections[call_id] = self

        request = self.receive_request(socket)

        if request is None:
            return None, None, False
        if self.check_cleanup():
            return request, None, False
        path = request.path
        self.path = path

        try:
            logger.debug(str(request))

            qa = request.path.query_args()
            if "socketwrench_input_id" in qa:
                prompt_id = qa["socketwrench_input_id"]
                prompt_input = NewInput.pending_inputs.get(prompt_id, None)
                if prompt_input is None:
                    # we have already responded to this, probably stale query args in a refresh, remove them
                    p = path
                    if "?" in p:
                        p = p.split("?")[0]
                        self.send_response(socket, RedirectResponse(p))
                    else:
                        raise BadRequest(b"Invalid input id")
                    return

                if "socketwrench_input_value" in qa:
                    try:
                        value = qa["socketwrench_input_value"]
                        if prompt_input:
                            response = prompt_input.client_input_queue.put(value)
                            result = prompt_input.server_result_queue.get()
                            self.send_response(socket, result)
                            return
                        else:
                            raise BadRequest(b"Invalid input id")
                    except Exception as e:
                        logger.error(f"Error handling input request: {e}")
                        logger.exception(e)
                        ise = InternalServerError()
                        self.send_response(socket, ise)
                        return
                elif "socketwrench_input_exit" in qa:
                    try:
                        if prompt_input:
                            response = prompt_input.client_input_queue.put({"socketwrench_input_exit": True})
                            result = prompt_input.server_result_queue.get()
                            self.send_response(socket, result)
                            return
                        else:
                            raise BadRequest(b"Invalid input id")
                    except Exception as e:
                        logger.error(f"Error handling input request: {e}")
                        logger.exception(e)
                        ise = InternalServerError()
                        self.send_response(socket, ise)
                        return
                else:
                    try:
                        logger.info(f"Prompting user for input: {prompt_id}, {prompt_input}")
                        if prompt_input:
                            response = prompt_input.prompt_for_input()
                            logger.info(f"Prompting user for input: {response}")
                            self.send_response(socket, response)
                            return
                        else:
                            raise BadRequest(b"Invalid input id")
                    except Exception as e:
                        logger.error(f"Error handling input request: {e}")
                        logger.exception(e)
                        ise = InternalServerError()
                        self.send_response(socket, ise)
                        return

            builtins.input = Connection.custom_input
            response = self.handler(request)

            if i := NewInput.pending_inputs.get(call_id):
                i.server_result_queue.put(bytes(response))
                del NewInput.pending_inputs[call_id]
                return

            logger.log(9, f"\t\t{response}")
            if self.check_cleanup():
                return request, response, False

            self.send_response(socket, response)
            return request, response, True
        except BadRequest as b:
            if i := NewInput.pending_inputs.get(call_id):
                i.server_result_queue.put(bytes(b))
                del NewInput.pending_inputs[call_id]
                return

            logger.error(f"Error handling request: {b}")
            logger.exception(b)
            try:
                self.send_response(socket, b)
            except Exception as e2:
                logger.error(f"Error sending response: {e2}")
        except Exception as e:
            ise = InternalServerError()
            if i := NewInput.pending_inputs.get(call_id):
                i.server_result_queue.put(bytes(ise))
                del NewInput.pending_inputs[call_id]
                return
            logger.error(f"Error handling request: {e}")
            logger.exception(e)
            try:
                self.send_response(socket, ise)
            except Exception as e2:
                logger.error(f"Error sending response: {e2}")

    def receive_request(self, connection_socket: socket.socket, chunk_size: int = None) -> Request:
        connection_socket.settimeout(self.timeout)
        if chunk_size is None:
            chunk_size = self.chunk_size

        new_line = b'\r\n'
        end_of_header = 2 * new_line

        request_data = b''
        while not self.cleanup_event or not self.cleanup_event.is_set():
            chunk = connection_socket.recv(chunk_size)
            request_data += chunk
            if end_of_header in request_data:
                break
            if not chunk:
                break

        if end_of_header not in request_data:
            raise BadRequest(b"Received empty chunk before end of header. Potential client issue or disconnection.")

        # Extract headers
        pre_body_bytes, body = request_data.split(end_of_header, 1)

        # Parsing Content-Length if present for requests with body
        lower = pre_body_bytes.lower()
        if b'content-length: ' in lower:
            length = int(lower.split(b'content-length: ')[1].split(new_line)[0])
            while len(body) < length and ((not self.cleanup_event) or (not self.cleanup_event.is_set())):
                body += connection_socket.recv(chunk_size)
        else:
            body = b''

        r = Request.from_components(pre_body_bytes, body, self.client_addr, connection_socket, origin=self.origin)
        return r

    def send_response(self, connection_socket: socket.socket, response: Response):
        connection_socket.sendall(bytes(response))
        connection_socket.shutdown(socket.SHUT_WR) # seems to be needed for linux?
        connection_socket.close()
        self.close()

    def check_cleanup(self):
        if self.cleanup_event and self.cleanup_event.is_set():
            self.close()
            return True
        return False

    def close(self):
        try:
            self.socket.shutdown(socket.SHUT_WR) # seems to be needed for linux?
        except Exception as e:
            # logger.warning(f"Error shutting down socket: {e}")
            pass

        try:
            self.socket.close()
        except Exception as e:
            # logger.warning(f"Error closing socket: {e}")
            pass

    def __repr__(self):
        if self._rep is None:
            r = ""
            if self.chunk_size != self.default_chunk_size:
                r += f", chunk_size={self.chunk_size}"

            self._rep = f'<{self.__class__.__name__}({self.socket}, {self.client_addr}, {self.cleanup_event}{r})>'
        return self._rep

