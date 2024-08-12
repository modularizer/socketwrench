from socketwrench.standardlib_dependencies import (
    dataclasses,
    datetime,
    dumps,
    socket,
    Path,
)


class HTTPVersion(str):
    """Represents an HTTP version string."""
    HTTP_0_9 = "HTTP/0.9"
    HTTP_1_0 = "HTTP/1.0"
    HTTP_1_1 = "HTTP/1.1"
    HTTP_2_0 = "HTTP/2.0"
    HTTP_3_0 = "HTTP/3.0"


class HTTPMethod(str):
    """Represents an HTTP method string."""
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    CONNECT = "CONNECT"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    PATCH = "PATCH"


class FileUploads(list):
    def __getattr__(self, item):
        for file in self:
            if item == file.name:
                return file
        return super().__getattr__(item)

    def __getitem__(self, item):
        if isinstance(item, int):
            return super().__getitem__(item)
        for file in self:
            if item == file.name:
                return file
        return super().__getitem__(item)

    def to_dict(self):
        return {file.name: file for file in self}


class Body(bytes):
    EMPTY = b""

    @property
    def files(self) -> FileUploads:
        return FileUploads()


class RequestBody(Body):
    def __new__(cls, data: bytes):
        return super().__new__(cls, data)


class FormBody(RequestBody):
    def __init__(self, data: bytes, boundary: bytes = b""):
        if not boundary:
            if not data.startswith(b"--"):
                raise InvalidFormError(b"data does not start with --")
            boundary = data.split(b"\r\n", 1)[0]
        if not data.startswith(boundary):
            raise InvalidFormError(f"data does not start with boundary ({boundary})".encode())
        parts = data.split(boundary)
        form_data = {}
        i = 0
        for part in parts[1:-1]:
            i += len(boundary)
            data_start=i
            i += len(part)
            if not part.strip(b'\r\n').strip(b'\n'):
                continue
            section = FormSection(data[data_start:i-2]) # -2 to remove the trailing \r\n
            form_data[section.name] = section
        self.boundary = boundary
        self.form_data: dict[str, FormSection] = FormData(form_data)

    @property
    def files(self) -> FileUploads:
        return FileUploads([v for v in self.form_data.values() if v.is_file])


class FormSection(bytes):
    def __new__(cls, data: bytes):
        if not b'\r\n\r\n' in data:
            raise InvalidFormError(b"Could not find form section headers")
        headers, body = data.split(b"\r\n\r\n", 1)
        hd = HeaderBytes(headers).to_dict()
        if "Content-Disposition" not in hd or not (cd := hd["Content-Disposition"]).startswith("form-data"):
            raise InvalidFormError(b"Cound not find 'Content-Disposition: form-data' in form section")
        if "filename" in cd:
            x = super().__new__(FileUpload, body)
        else:
            x = super().__new__(cls, body)
        x._set_headers(headers)
        return x

    def _set_headers(self, headers: bytes):
        self.section_header_bytes = HeaderBytes(headers)
        self.section_headers = self.section_header_bytes.to_dict()
        cd = self.section_headers["Content-Disposition"]
        cd_info_parts = [k.split('=', 1) for k in cd.split(";", 1)[1].split(";") if '=' in k]
        info = {k.strip(): v.strip() for k, v in cd_info_parts}
        if "name" not in info:
            raise InvalidFormError(b"Could not find 'name' in form section")
        self.name = info.get("name").strip('"')
        self.filename = FileName(info["filename"].strip('"')) if "filename" in info else None
        self.info = info

    @property
    def is_file(self):
        return self.filename is not None

    def decode(self, encoding="utf-8", errors = "strict"):
        return FormValue(self)


class FormValue(str):
    def __new__(cls, s: str):
        if isinstance(s, FormSection):
            x = super().__new__(cls, bytes(s).decode())
            x._set_headers(s.section_header_bytes, s.section_headers, s.name, s.filename, s.info)
        else:
            x = super().__new__(cls, s)
        return x

    def _set_headers(self,
                     section_header_bytes,
                     section_headers,
                        name,
                        filename,
                        info):
        self.section_header_bytes = section_header_bytes
        self.section_headers = section_headers
        self.name = name
        self.filename = filename
        self.info = info

    @property
    def is_file(self):
        return False


class FileName(str):
    pass


class FormData(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for k, v in self.items():
            if not v.is_file:
                v = v.decode()
                self[k] = v

    def __getattr__(self, item) -> FormSection:
        return self[item]


class FileUpload(FormSection):
    default_save_folder = None
    clear_on_close = True

    def _set_headers(self, headers: bytes):
        super()._set_headers(headers)
        self.pos = 0
        self.mode = "rb"
        self.opened = True
        self.cleared = False
        self.content_type = ContentType(self.section_headers.get("Content-Type", ""))
        self.filetype = FileType(self.content_type)

    def save(self, dst=None):
        if dst is None:
            dst = self.default_save_folder
        if dst is None:
            dst = Path.cwd()
        dst = Path(dst)
        if dst.exists() and dst.is_dir():
            dst = dst / self.filename
        with dst.open("wb") as f:
            f.write(self)
        return dst

    def open(self, mode: str = "rb") -> "FileUpload":
        if mode not in ["r", "rb"]:
            raise ValueError("Invalid mode.")
        if self.cleared:
            raise ValueError("Data has been cleared.")
        self.mode = mode
        return self

    def read(self, n: int = -1) -> bytes:
        if self.cleared:
            raise ValueError("Data has been cleared.")
        if not self.opened:
            raise ValueError("I/O operation on closed file.")
        if n == -1:
            n = len(self)
        if (self.pos + n) >= len(self):
            raise EOFError("End of file.")
        result = self[self.pos:self.pos + n]
        self.pos += n
        if self.mode == "r":
            return result.decode()
        return result

    def readline(self, __size = -1):
        if self.cleared:
            raise ValueError("Data has been cleared.")
        if not self.opened:
            raise ValueError("I/O operation on closed file.")
        if __size == -1:
            __size = len(self) - self.pos

        if self.mode == "r":
            line = ""
            for i in range(__size):
                try:
                    char = self.read(1)
                except EOFError:
                    break
                line += char
                if char == "\n":
                    break
        else:
            line = b''
            for i in range(__size):
                try:
                    char = self.read(1)
                except EOFError:
                    break
                line += char
                if char == b"\n":
                    break
        return line

    def readlines(self, __hint = -1):
        if self.cleared:
            raise ValueError("Data has been cleared.")
        if not self.opened:
            raise ValueError("I/O operation on closed file.")
        if __hint == -1:
            __hint = len(self) - self.pos
        lines = []
        while True:
            line = self.readline(__hint)
            __hint -= len(line)
            if not line:
                break
            lines.append(line)
        return lines

    def readinto(self, __buffer):
        if self.cleared:
            raise ValueError("Data has been cleared.")
        if not self.opened:
            raise ValueError("I/O operation on closed file.")
        __buffer[0:len(self)] = self
        return len(self)

    def readall(self):
        if self.cleared:
            raise ValueError("Data has been cleared.")
        if not self.opened:
            raise ValueError("I/O operation on closed file.")
        return self

    def seek(self, pos: int):
        if self.cleared:
            raise ValueError("Data has been cleared.")
        if not self.opened:
            raise ValueError("I/O operation on closed file.")
        if pos < 0:
            raise ValueError("Negative seek position.")
        if pos >= len(self):
            raise EOFError("End of file.")
        self.pos = pos

    def tell(self) -> int:
        if self.cleared:
            raise ValueError("Data has been cleared.")
        if not self.opened:
            raise ValueError("I/O operation on closed file.")
        return self.pos

    def close(self, clear=None):
        self.opened = False
        if clear is None:
            clear = self.clear_on_close
        if clear:
            self.clear()

    def __repr__(self) -> str:
        return f"FileUpload({self.filename}|{self.content_type}|{len(self)} bytes)"

    def __str__(self) -> str:
        return self.__repr__()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.clear()

    def clear(self):
        self.opened = False
        self.cleared = True

File = FileUpload
Upload = FileUpload
Files = FileUploads
Uploads = FileUploads
Form = FormData


class _ContentType:
    content_types = {
        "html": "text/html",
        "css": "text/css",
        "js": "application/javascript",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "svg": "image/svg+xml",
        "bmp": "image/bmp",
        "tiff": "image/tiff",
        "ico": "image/x-icon",
        "webp": "image/webp",
        "stl": "model/stl",
        "obj": "model/obj",
        "fbx": "model/fbx",
        "glb": "model/gltf-binary",
        "gltf": "model/gltf+json",
        "3ds": "model/3ds",
        "3mf": "model/3mf",
        "json": "application/json",
        "yml": "application/x-yaml",
        "yaml": "application/x-yaml",
        "doc": "application/msword",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls": "application/vnd.ms-excel",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt": "application/vnd.ms-powerpoint",
        "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt": "application/vnd.oasis.opendocument.text",
        "ods": "application/vnd.oasis.opendocument.spreadsheet",
        "odp": "application/vnd.oasis.opendocument.presentation",
        "odg": "application/vnd.oasis.opendocument.graphics",
        "odf": "application/vnd.oasis.opendocument.formula",
        "pdf": "application/pdf",
        "zip": "application/zip",
        "tar": "application/x-tar",
        "gz": "application/gzip",
        "mp3": "audio/mpeg",
        "mp4": "video/mp4",
        "webm": "video/webm",
        "ogg": "audio/ogg",
        "wav": "audio/wav",
        "txt": "text/plain",
        "csv": "text/csv",
        "xml": "text/xml",
        "md": "text/markdown",
        "py": "text/x-python",
        "c": "text/x-c",
        "cpp": "text/x-c++",
        "h": "text/x-c-header",
        "hs": "text/x-haskell",
        "java": "text/x-java",
        "sh": "text/x-shellscript",
        "bat": "text/x-batch",
        "ps1": "text/x-powershell",
        "rb": "text/x-ruby",
        "rs": "text/x-rust",
        "go": "text/x-go",
        "php": "text/x-php",
        "pl": "text/x-perl",
        "swift": "text/x-swift",
        "asm": "text/x-asm",
        "toml": "application/toml",
        "ini": "text/x-ini",
        "cfg": "text/x-config",
        "conf": "text/x-config",
        "gitignore": "text/x-gitignore",
        "dockerfile": "text/x-dockerfile",
        None: "application/octet-stream"
    }
    file_types = {v: k for k, v in content_types.items()}

    @property
    def filetype(self):
        return FileType(self)

    @property
    def extension(self):
        return self.filetype.extension

    @classmethod
    def get_content_type(cls, suffix: str):
        return cls.content_types.get(suffix.lower(), cls.content_types[cls.default_content_type])

    def get_extension(self, content_type: str):
        for k, v in self.content_types.items():
            if v == content_type:
                return "." + k
        return ""


class ContentType(_ContentType, str):
    def __instancecheck__(self, instance):
        return isinstance(instance, str) and instance in self.content_types


class FileType(_ContentType, str):
    def __new__(cls, s):
        s = str(s)
        s = s.lower().strip()
        if s.startswith('.'):
            s = s[1:]
        if s in cls.file_types:
            s = cls.file_types[s]

        return super().__new__(cls, s)

    @property
    def content_type(self):
        return ContentType(self)

    def __instancecheck__(self, instance):
        return isinstance(instance, str) and instance in self.content_types


content_types = {FileType(v): ContentType(v) for k, v in ContentType.content_types.items()}
file_types = {v: k for k, v in content_types.items()}
ContentType.file_types = file_types
ContentType.content_types = content_types



class Headers(dict):
    EMPTY = {}
    def __init__(self, d):
        d = {self.cc(k): v for k, v in d.items()}
        super().__init__(d)

    @staticmethod
    def cc(k):
        # replace the first character following a hyphen or a space with its uppercase equivalent
        s = ""
        cap = False
        for c in k:
            if cap:
                s += c.upper()
                cap = False
            elif c in "- ":
                cap = True
            else:
                s += c.lower()
        return s

    def to_string(self) -> str:
        s = ""
        for k, v in self.items():
            s += f"{k}: {v}\r\n"
        return s

    def __str__(self):
        return self.to_string()

    def __getitem__(self, item):
        return super().__getitem__(self.cc(item))

    def __setitem__(self, key, value):
        super().__setitem__(self.cc(key), value)

    def __delitem__(self, item):
        return super().__delitem__(self.cc(item))

    def __contains__(self, item):
        return super().__contains__(self.cc(item))

    def get(self, item, default=None):
        return super().get(self.cc(item), default)

    def to_bytes(self) -> bytes:
        return self.to_string().encode()


class HeaderBytes(bytes):
    EMPTY = b""

    def __new__(cls, s):
    # def __new__(cls, s: bytes | Headers | dict[str, str]):
        if isinstance(s, Headers):
            s = s.to_bytes()
        elif isinstance(s, dict):
            s = Headers(s).to_bytes()
        return super().__new__(cls, s)

    def to_string(self):
        return self.decode()

    def to_dict(self) -> dict:
        lines = self.decode().splitlines()
        items = [v.split(":", 1) for v in lines if ":" in v]
        d = {k.strip(): v.strip() for k, v in items}
        return Headers(d)

    def __iter__(self):
        return iter(self.to_dict())


class RequestPath(str):
    EMPTY = ""
    BASE = "/"

    def query(self) -> str:
        """Extracts the query string from the path."""
        if "?" not in self:
            return ""
        q = self.split("?", 1)[1]
        return "?" + q

    def route(self) -> str:
        """Extracts the path from the path and remove the query."""
        p = self.split("?", 1)[0]
        return url_decode(p)

    def query_args(self) -> dict[str, str]:
        """Extracts the query string from the path and parses into a dictionary."""
        q = self.query()
        if not q:
            return {}
        q = q[1:]
        items = [v.split("=", 1) if '=' in v else (v, "") for v in q.split("&")]
        d = {url_decode_query(k): url_decode_query(v) for k, v in items}
        return d


class ClientAddr(str):
    def __new__(cls, host_port):
    # def __new__(cls, host_port: str | tuple[str, int]):
        if isinstance(host_port, tuple):
            host = host_port[0]
            port = host_port[1]
        else:
            host = host_port
            port = None
        self = super().__new__(cls, host)
        self.host = host
        self.port = port
        return self


class Request:
    @classmethod
    def from_components(cls, pre_body_bytes: bytes, body: bytes, client_addr: str, connection_socket: socket = None, origin: str = "") -> "Request":
    # def from_components(cls, pre_body_bytes: bytes, body: bytes, client_addr: str | tuple[str, int], connection_socket: socket.socket = None) -> "Request":
        """Create a Request object from a header string and a body bytes object."""
        i = pre_body_bytes.index(b"\r\n")
        first_line = pre_body_bytes[:i].decode()
        method, path, version = first_line.split(" ")
        header_bytes = pre_body_bytes[i + 2:]
        return cls(method, path, version, header_bytes, body, client_addr, connection_socket, origin=origin)

    def __init__(self,
                 method: str = HTTPMethod.GET,
                 path: str = RequestPath.BASE,
                 version: str = HTTPVersion.HTTP_1_1,
                 header: bytes = HeaderBytes.EMPTY,
                 body: bytes = RequestBody.EMPTY,
                 client_addr: str = None,
                 connection_socket: socket = None,
                 origin: str = ""
                 ):
        """Parsed HTML Request bytes broken down into its components.

        Args:
            method: str | HTTPMethod
            path: str | RequestPath
            version: str | HTTPVersion
            header: bytes | HeaderBytes | Headers | dict[str, str]
            body: bytes | RequestBody
            client_addr: str | tuple[str, int] | None
            connection_socket: socket.socket | None
        """
        self.method = HTTPMethod(method)
        self.path = RequestPath(path)
        self.version = HTTPVersion(version)
        self.header_bytes = HeaderBytes(header)
        self._headers = None
        is_form_data = "form-data" in self.headers.get("Content-Type", "")
        self.body = RequestBody(body) if not is_form_data else FormBody(body)
        self.client_addr = ClientAddr(client_addr) if client_addr else None
        self.connection_socket = connection_socket
        self.origin = origin

    @property
    def headers(self) -> Headers:
        if self._headers is None:
            self._headers = Headers(self.header_bytes.to_dict())
        return self._headers

    def to_string(self) -> str:
        return f'{self.method} {self.path} {self.version}\r\n{self.headers}\r\n\r\n{self.body}'

    def to_json(self) -> str:
        return dumps({
            "method": self.method,
            "path": self.path,
            "version": self.version,
            "headers": self.headers,
            "body": str(self.body),
            "client_addr": self.client_addr
        })

    @property
    def form_data(self) -> FormData:
        if isinstance(self.body, FormBody):
            return self.body.form_data
        return FormData()

    @property
    def files(self) -> FileUploads:
        return self.body.files

    def __str__(self):
        return f"{self.method} {self.origin}{self.path} from {self.client_addr}"

    def __repr__(self):
        ca = f'"{self.client_addr}"' if isinstance(self.client_addr, str) else self.client_addr
        r = f'<Request("{self.method}","{self.path}", "{self.version}", {bytes(self.header_bytes)}, {bytes(self.body)}, {ca}, {self.connection_socket}, "{self.origin}")>'
        r = r.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        if len(r) > 100:
            r = r[:100] + "..."
        return r


class ResponseBody(Body):
    pass


class HTTPStatusCode(int):
    # Informational Responses
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101
    PROCESSING = 102
    EARLY_HINTS = 103

    # Successful Responses
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206
    MULTI_STATUS = 207
    ALREADY_REPORTED = 208
    IM_USED = 226

    # Redirection Messages
    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    FOUND = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    USE_PROXY = 305
    TEMPORARY_REDIRECT = 307
    PERMANENT_REDIRECT = 308

    # Client Error Responses
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    GONE = 410
    LENGTH_REQUIRED = 411
    PRECONDITION_FAILED = 412
    PAYLOAD_TOO_LARGE = 413
    URI_TOO_LONG = 414
    UNSUPPORTED_MEDIA_TYPE = 415
    RANGE_NOT_SATISFIABLE = 416
    EXPECTATION_FAILED = 417
    IM_A_TEAPOT = 418
    MISDIRECTED_REQUEST = 421
    UNPROCESSABLE_ENTITY = 422
    LOCKED = 423
    FAILED_DEPENDENCY = 424
    TOO_EARLY = 425
    UPGRADE_REQUIRED = 426
    PRECONDITION_REQUIRED = 428
    TOO_MANY_REQUESTS = 429
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431
    UNAVAILABLE_FOR_LEGAL_REASONS = 451

    # Server Error Responses
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504
    HTTP_VERSION_NOT_SUPPORTED = 505
    VARIANT_ALSO_NEGOTIATES = 506
    INSUFFICIENT_STORAGE = 507
    LOOP_DETECTED = 508
    NOT_EXTENDED = 510
    NETWORK_AUTHENTICATION_REQUIRED = 511

    def __new__(cls, status_code: int, phrase: str = None):
        self = super().__new__(cls, status_code)
        self._phrase = phrase
        return self

    def phrase(self) -> str:
        if self._phrase is None:
            for k, v in self.__class__.__dict__.items():
                if v == self:
                    self._phrase = k.replace("_", " ")
                    break
            else:
                self._phrase = "Unknown"
        return self._phrase

    def is_informational(self) -> bool:
        return 100 <= self <= 199

    def is_successful(self) -> bool:
        return 200 <= self <= 299

    def is_redirect(self) -> bool:
        return 300 <= self <= 399

    def is_client_error(self) -> bool:
        return 400 <= self <= 499

    def is_server_error(self) -> bool:
        return 500 <= self <= 599

    def __str__(self) -> str:
        return f'{int(self)} {self.phrase()}'


status_code_names = {v: k for k, v in HTTPStatusCode.__dict__.items() if (not k.startswith("_")) and isinstance(v, int)}
for k, v in HTTPStatusCode.__dict__.items():
    if isinstance(v, int):
        setattr(HTTPStatusCode, k, HTTPStatusCode(v, k.replace("_", " ")))


class ResponseTypehint:
    def __init__(self, content_type: str):
        self.content_type = content_type


class ResponseType(type):
    def __getitem__(self, item):
        class TypedResponse(Response):
            default_content_type = item
        return TypedResponse


class Response(Exception, metaclass=ResponseType):
    default_content_type = None
    default_status_code = HTTPStatusCode.OK

    @classmethod
    def from_status_code(cls, status_code: int):
        class StatusCodeResponse(cls):
            default_status_code = status_code

            def __init__(self,
                 body: bytes = ResponseBody.EMPTY,
                 *args,
                 **kwargs
                 ):
                if isinstance(body, str):
                    body = body.encode()
                super().__init__(body, *args, **kwargs)

        StatusCodeResponse.__name__ = status_code_names.get(status_code, str(status_code))
        return StatusCodeResponse

    def __new__(cls, body: bytes = ResponseBody.EMPTY,
                status_code: int = None,
                headers: dict = HeaderBytes.EMPTY,
                version: str = HTTPVersion.HTTP_1_1,
                raw: bool = False,
                **headers_kwargs):
        # If the body is already a Response instance, return it
        if isinstance(body, Response):
            return body

        if raw:
            return super(RawResponse, cls).__new__(cls)

        # Create an instance of the appropriate subclass based on the body type
        if cls is Response or cls.__init__ is Response.__init__:
            if isinstance(body, (bytes, memoryview)):
                return super(Response, cls).__new__(cls)
            elif isinstance(body, str):
                return super(Response, HTMLResponse).__new__(HTMLResponse)
            elif isinstance(body, Path):
                return super(Response, FileResponse).__new__(FileResponse)
            elif isinstance(body, Exception):
                return super(Response, ErrorResponse).__new__(ErrorResponse)
            else:
                return super(Response, JSONResponse).__new__(JSONResponse)
        else:
            return super(Response, cls).__new__(cls)

    def __init__(self,
                 body: bytes = ResponseBody.EMPTY,
                 status_code: int = None,
                 headers: dict = HeaderBytes.EMPTY,
                 version: str = HTTPVersion.HTTP_1_1,
                 raw: bool = False,
                 **headers_kwargs
                 ):
        if status_code is None:
            status_code = self.default_status_code
        self.status_code = HTTPStatusCode(status_code)
        self.version = HTTPVersion(version)
        self.header_bytes = HeaderBytes(headers)
        self.headers = Headers(self.header_bytes.to_dict())
        for k, v in headers_kwargs.items():
            t = k.replace("_", " ").title().replace(" ", "-")
            if not isinstance(v, str):
                v = dumps(v)
            self.headers[t] = v
        self.body = ResponseBody(body)
        self.raw = raw
        super().__init__(self.body, self.status_code, self.headers, self.version)

    def pre_body_bytes(self) -> bytes:
        return f'{self.version} {self.status_code}\r\n{self.headers}\r\n'.encode()

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.status_code} {self.body[:80]}>"

    def __bytes__(self):
        return self.pre_body_bytes() + self.body

    def __buffer__(self, flags):
        return memoryview(bytes(self))


class RawResponse(Response):
    def __init__(self, full_response_bytes: bytes, raw: bool = True, **kwargs):
        if not raw:
            raise ValueError("RawResponse must be raw.")
        self.full_response_bytes = full_response_bytes
        self.version, self.status_code, self.headers, self.body = self.parse(full_response_bytes)
        self.raw = raw

    @staticmethod
    def parse(full_response_bytes: bytes):
        try:
            # get the first two lines
            first_line_end = full_response_bytes.index(b"\r\n")
            first_line = full_response_bytes[:first_line_end]
            version, status_code, phrase = first_line.split(b" ", 2)
            # get the headers
            header_end = first_line_end + 2 + full_response_bytes[first_line_end + 2:].index(b"\r\n\r\n")
            header_bytes = full_response_bytes[first_line_end + 2:header_end]

            version = HTTPVersion(version)
            status_code = HTTPStatusCode(int(status_code), phrase)
            header_bytes = HeaderBytes(header_bytes)
            headers = Headers(header_bytes.to_dict())
            body = ResponseBody(full_response_bytes[header_end + 4:])
            return version, status_code, headers, body
        except:
            return None, None, None, None

    def __bytes__(self):
        return bytes(self.full_response_bytes)

    def __buffer__(self, flags):
        return self.full_response_bytes if isinstance(self.full_response_bytes, memoryview) else memoryview(self.full_response_bytes)


class InformationalResponse(Response):
    default_status_code = 100

    def __subclasshook__(cls, __subclass):
        return super().__subclasshook__(__subclass) or (
                    cls is InformationalResponse and 100 <= __subclass.default_status_code <= 199)

class SuccessResponse(Response):
    default_status_code = 200

    def __subclasshook__(cls, __subclass):
        return super().__subclasshook__(__subclass) or (
                    cls is SuccessResponse and 200 <= __subclass.default_status_code <= 299)


class RedirectionResponse(Response):
    default_status_code = 300

    def __subclasshook__(cls, __subclass):
        return super().__subclasshook__(__subclass) or (cls is RedirectionResponse and 300 <= __subclass.default_status_code <= 399)


class ClientError(Response):
    default_status_code = 400

    def __subclasshook__(cls, __subclass):
        return super().__subclasshook__(__subclass) or (
                    cls is ClientError and 400 <= __subclass.default_status_code <= 499)


class BadRequest(ClientError):
    pass


class InvalidFormError(BadRequest):
    pass


class ServerError(Response):
    default_status_code = 500

    def __subclasshook__(cls, __subclass):
        return super().__subclasshook__(__subclass) or (cls is ServerError and 500 <= __subclass.default_status_code <= 599)


class InternalServerError(ServerError):
    pass


class HTTPStatusCodeResponses:
    # Informational Responses
    CONTINUE = InformationalResponse.from_status_code(HTTPStatusCode.CONTINUE)
    SWITCHING_PROTOCOLS = InformationalResponse.from_status_code(HTTPStatusCode.SWITCHING_PROTOCOLS)
    PROCESSING = InformationalResponse.from_status_code(HTTPStatusCode.PROCESSING)
    EARLY_HINTS = InformationalResponse.from_status_code(HTTPStatusCode.EARLY_HINTS)

    # Successful Responses
    OK = SuccessResponse.from_status_code(HTTPStatusCode.OK)
    CREATED = SuccessResponse.from_status_code(HTTPStatusCode.CREATED)
    ACCEPTED = SuccessResponse.from_status_code(HTTPStatusCode.ACCEPTED)
    NON_AUTHORITATIVE_INFORMATION = SuccessResponse.from_status_code(HTTPStatusCode.NON_AUTHORITATIVE_INFORMATION)
    NO_CONTENT = SuccessResponse.from_status_code(HTTPStatusCode.NO_CONTENT)
    RESET_CONTENT = SuccessResponse.from_status_code(HTTPStatusCode.RESET_CONTENT)
    PARTIAL_CONTENT = SuccessResponse.from_status_code(HTTPStatusCode.PARTIAL_CONTENT)
    MULTI_STATUS = SuccessResponse.from_status_code(HTTPStatusCode.MULTI_STATUS)
    ALREADY_REPORTED = SuccessResponse.from_status_code(HTTPStatusCode.ALREADY_REPORTED)
    IM_USED = SuccessResponse.from_status_code(HTTPStatusCode.IM_USED)

    # Redirection Messages
    MULTIPLE_CHOICES = RedirectionResponse.from_status_code(HTTPStatusCode.MULTIPLE_CHOICES)
    MOVED_PERMANENTLY = RedirectionResponse.from_status_code(HTTPStatusCode.MOVED_PERMANENTLY)
    FOUND = RedirectionResponse.from_status_code(HTTPStatusCode.FOUND)
    SEE_OTHER = RedirectionResponse.from_status_code(HTTPStatusCode.SEE_OTHER)
    NOT_MODIFIED = RedirectionResponse.from_status_code(HTTPStatusCode.NOT_MODIFIED)
    USE_PROXY = RedirectionResponse.from_status_code(HTTPStatusCode.USE_PROXY)
    TEMPORARY_REDIRECT = RedirectionResponse.from_status_code(HTTPStatusCode.TEMPORARY_REDIRECT)
    PERMANENT_REDIRECT = RedirectionResponse.from_status_code(HTTPStatusCode.PERMANENT_REDIRECT)

    # Client Error Responses
    BAD_REQUEST = BadRequest
    UNAUTHORIZED = ClientError.from_status_code(HTTPStatusCode.UNAUTHORIZED)
    PAYMENT_REQUIRED = ClientError.from_status_code(HTTPStatusCode.PAYMENT_REQUIRED)
    FORBIDDEN = ClientError.from_status_code(HTTPStatusCode.FORBIDDEN)
    NOT_FOUND = ClientError.from_status_code(HTTPStatusCode.NOT_FOUND)
    METHOD_NOT_ALLOWED = ClientError.from_status_code(HTTPStatusCode.METHOD_NOT_ALLOWED)
    NOT_ACCEPTABLE = ClientError.from_status_code(HTTPStatusCode.NOT_ACCEPTABLE)
    PROXY_AUTHENTICATION_REQUIRED = ClientError.from_status_code(HTTPStatusCode.PROXY_AUTHENTICATION_REQUIRED)
    REQUEST_TIMEOUT = ClientError.from_status_code(HTTPStatusCode.REQUEST_TIMEOUT)
    CONFLICT = ClientError.from_status_code(HTTPStatusCode.CONFLICT)
    GONE = ClientError.from_status_code(HTTPStatusCode.GONE)
    LENGTH_REQUIRED = ClientError.from_status_code(HTTPStatusCode.LENGTH_REQUIRED)
    PRECONDITION_FAILED = ClientError.from_status_code(HTTPStatusCode.PRECONDITION_FAILED)
    PAYLOAD_TOO_LARGE = ClientError.from_status_code(HTTPStatusCode.PAYLOAD_TOO_LARGE)
    URI_TOO_LONG = ClientError.from_status_code(HTTPStatusCode.URI_TOO_LONG)
    UNSUPPORTED_MEDIA_TYPE = ClientError.from_status_code(HTTPStatusCode.UNSUPPORTED_MEDIA_TYPE)
    RANGE_NOT_SATISFIABLE = ClientError.from_status_code(HTTPStatusCode.RANGE_NOT_SATISFIABLE)
    EXPECTATION_FAILED = ClientError.from_status_code(HTTPStatusCode.EXPECTATION_FAILED)
    IM_A_TEAPOT = ClientError.from_status_code(HTTPStatusCode.IM_A_TEAPOT)
    MISDIRECTED_REQUEST = ClientError.from_status_code(HTTPStatusCode.MISDIRECTED_REQUEST)
    UNPROCESSABLE_ENTITY = ClientError.from_status_code(HTTPStatusCode.UNPROCESSABLE_ENTITY)
    LOCKED = ClientError.from_status_code(HTTPStatusCode.LOCKED)
    FAILED_DEPENDENCY = ClientError.from_status_code(HTTPStatusCode.FAILED_DEPENDENCY)
    TOO_EARLY = ClientError.from_status_code(HTTPStatusCode.TOO_EARLY)
    UPGRADE_REQUIRED = ClientError.from_status_code(HTTPStatusCode.UPGRADE_REQUIRED)
    PRECONDITION_REQUIRED = ClientError.from_status_code(HTTPStatusCode.PRECONDITION_REQUIRED)
    TOO_MANY_REQUESTS = ClientError.from_status_code(HTTPStatusCode.TOO_MANY_REQUESTS)
    REQUEST_HEADER_FIELDS_TOO_LARGE = ClientError.from_status_code(HTTPStatusCode.REQUEST_HEADER_FIELDS_TOO_LARGE)
    UNAVAILABLE_FOR_LEGAL_REASONS = ClientError.from_status_code(HTTPStatusCode.UNAVAILABLE_FOR_LEGAL_REASONS)

    # Server Error Responses
    INTERNAL_SERVER_ERROR = InternalServerError
    NOT_IMPLEMENTED = ServerError.from_status_code(HTTPStatusCode.NOT_IMPLEMENTED)
    BAD_GATEWAY = ServerError.from_status_code(HTTPStatusCode.BAD_GATEWAY)
    SERVICE_UNAVAILABLE = ServerError.from_status_code(HTTPStatusCode.SERVICE_UNAVAILABLE)
    GATEWAY_TIMEOUT = ServerError.from_status_code(HTTPStatusCode.GATEWAY_TIMEOUT)
    HTTP_VERSION_NOT_SUPPORTED = ServerError.from_status_code(HTTPStatusCode.HTTP_VERSION_NOT_SUPPORTED)
    VARIANT_ALSO_NEGOTIATES = ServerError.from_status_code(HTTPStatusCode.VARIANT_ALSO_NEGOTIATES)
    INSUFFICIENT_STORAGE = ServerError.from_status_code(HTTPStatusCode.INSUFFICIENT_STORAGE)
    LOOP_DETECTED = ServerError.from_status_code(HTTPStatusCode.LOOP_DETECTED)
    NOT_EXTENDED = ServerError.from_status_code(HTTPStatusCode.NOT_EXTENDED)
    NETWORK_AUTHENTICATION_REQUIRED = ServerError.from_status_code(HTTPStatusCode.NETWORK_AUTHENTICATION_REQUIRED)


class RawResponse(Response):
    def __init__(self, full_response_bytes: bytes, raw: bool = True, **kwargs):
        if not raw:
            raise ValueError("RawResponse must be raw.")
        self.full_response_bytes = full_response_bytes
        self.version, self.status_code, self.headers, self.body = self.parse(full_response_bytes)
        self.raw = raw

    @staticmethod
    def parse(full_response_bytes: bytes):
        try:
            # get the first two lines
            first_line_end = full_response_bytes.index(b"\r\n")
            first_line = full_response_bytes[:first_line_end]
            version, status_code, phrase = first_line.split(b" ", 2)
            # get the headers
            header_end = first_line_end + 2 + full_response_bytes[first_line_end + 2:].index(b"\r\n\r\n")
            header_bytes = full_response_bytes[first_line_end + 2:header_end]

            version = HTTPVersion(version)
            status_code = HTTPStatusCode(int(status_code), phrase)
            header_bytes = HeaderBytes(header_bytes)
            headers = Headers(header_bytes.to_dict())
            body = ResponseBody(full_response_bytes[header_end + 4:])
            return version, status_code, headers, body
        except:
            return None, None, None, None

    def __bytes__(self):
        return bytes(self.full_response_bytes)

    def __buffer__(self, flags):
        return self.full_response_bytes if isinstance(self.full_response_bytes, memoryview) else memoryview(self.full_response_bytes)


class FileResponse(SuccessResponse):
    content_types = FileType.content_types

    default_content_type = None

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self,
                 *a,
                 body: bytes = b"",
                 path: str = None,
                 filename: str = None,
                 extension: str = None,
                 status_code: int = 200,
                 headers: dict = None,
                 content_type: str = None,
                 download: bool = False,
                 version: str = "HTTP/1.1",
                 raw: bool = False):
        if raw:
            raise NotImplementedError
        if content_type is None and self.default_content_type is not None:
            content_type = self.default_content_type
        if content_type is None and extension is not None:
            content_type = self.get_content_type(extension.lstrip("."))

        if a:
            if len(a) == 1:
                if isinstance(a[0], str):
                    if Path(a[0]).exists():
                        path = Path(a[0])
                    else:
                        body = a[0].encode()
                elif isinstance(a[0], Path):
                    path = a[0]
                else:
                    body = a[0]

        path = Path(path) if path else Path(".") if not body else None
        if filename is None:
            if path:
                filename = path.name
            elif extension:
                filename = "file." + extension.lstrip(".")
            elif content_type:
                filename = "file" + self.get_extension(content_type)
            else:
                filename = "file"
        if path and body:
            raise ValueError(f"Cannot have both a path and data: {path}, {body}")
        if not path and not body:
            raise ValueError("Must have either a path or data.")
        if body:
            if isinstance(body, str):
                body = body.encode()
            elif isinstance(body, bytes):
                pass
            elif isinstance(a[0], (bytearray, memoryview)):
                body = bytes(a[0])
            elif hasattr(a[0], "read"):
                body = a[0].read()
            elif hasattr(a[0], "tobytes"):
                body = a[0].tobytes()
            elif hasattr(a[0], "to_bytes"):
                body = a[0].to_bytes()
            elif hasattr(a[0], "dumps"):
                body = (a[0]).dumps().encode()
            elif isinstance(a[0], dict):
                body = dumps(a[0]).encode()
            else:
                raise ValueError(f"Invalid argument: {a[0]}")

        if headers is None:
            headers = {}
        headers = Headers(headers)

        if download and "Content-Disposition" not in headers:
            headers["Content-Disposition"] = f'attachment; filename="{filename}"'

        # add headers related to file stats
        if "Content-Length" not in headers:
            headers["Content-Length"] = str(path.stat().st_size) if path else str(len(body))
        if "Last-Modified" not in headers:
            headers["Last-Modified"] = datetime.fromtimestamp(path.stat().st_mtime).isoformat() if path else datetime.now().isoformat()

        if path and path.is_dir():
            from socketwrench.standardlib_dependencies import TemporaryFile, ZipFile
            # zip the directory to a TemporaryFile
            with TemporaryFile() as f:
                with ZipFile(f, "w") as z:
                    for p in path.iterdir():
                        z.write(p, p.name)
                f.seek(0)
                super().__init__(f.read(),
                                 status_code=status_code,
                                 headers=headers,
                                 content_type="application/zip",
                                 version=version)
        elif path:
            if content_type is None:
                content_type = self.get_content_type(path.suffix[1:])

            if not path.exists():
                raise FileNotFoundError(f"No such file or directory: '{path}'")
            with path.open("rb") as f:
                f.seek(0)
                b = f.read()

            super().__init__(b,
                             status_code=status_code,
                             headers=headers,
                             content_type=content_type,
                             version=version)
        else:
            super().__init__(body,
                             status_code=status_code,
                             headers=headers,
                             content_type=content_type,
                             version=version)

    def __str__(self):
        ct = self.headers.get("Content-Type", "application/octet-stream")
        return f"{self.__class__.__name__}[{ct}] {self.status_code} {self.body[:80]}"

    def get_content_type(self, suffix: str):
        return self.content_types.get(suffix.lower(), self.content_types[self.default_content_type])

    def get_extension(self, content_type: str):
        for k, v in self.content_types.items():
            if v == content_type:
                return "." + k
        return ""


# define a class such that FileTypeResponse[content_type] is a subclass of FileResponse


class FileTypeResponseMeta(type):
    def __getitem__(self, content_type):
        return self.get_class(content_type)

    @classmethod
    def get_class(cls, content_type, write_function=None):
        # Create a new subclass of FileResponse with a custom content type
        if content_type[0] == "." and content_type[1:] in FileResponse.content_types:
            content_type = FileResponse.content_types[content_type[1:]]

        class TypedFileResponse(FileResponse):
            default_content_type = content_type

            def __init__(self,
                         *a,
                         body: bytes = b"",
                         path: str = None,
                         filename: str = None,
                         extension: str = None,
                         status_code: int = 200,
                         headers: dict = None,
                         content_type: str = None,
                         download: bool = False,
                         version: str = "HTTP/1.1"):
                if write_function:
                    r = write_function(*a)
                    a = (r,)
                super().__init__(*a,
                                    body=body,
                                    path=path,
                                    filename=filename,
                                    extension=extension,
                                    status_code=status_code,
                                    headers=headers,
                                    content_type=content_type,
                                    download=download,
                                    version=version)


        # Generate a class name based on the content type
        ct_name = content_type.split("/")[-1].replace(".", "").replace("-", "").upper()
        TypedFileResponse.__name__ = f"{ct_name}FileResponse"

        return TypedFileResponse

    def __subclasscheck__(self, subclass):
        return issubclass(subclass, FileResponse)


class FileTypeResponse(metaclass=FileTypeResponseMeta):
    def __new__(cls, *args, **kwargs):
        return FileTypeResponseMeta.get_class(*args, **kwargs)


class HTMLResponse(SuccessResponse):

    def __init__(self, html: str, status_code: int = 200, headers: dict = None, version: str = "HTTP/1.1", raw: bool = False):
        if headers is None:
            headers = {}
        if "Content-Type" not in headers:
            headers["Content-Type"] = "text/html"
        Response.__init__(self, html.encode(), status_code, headers, version, raw=raw)


class StandardHTMLResponse(HTMLResponse):
    def __init__(self, body: str, title = "", favicon=None,  scripts: list = None, stylesheets = None, status_code: int = 200, headers: dict = None, version: str = "HTTP/1.1", raw: bool = False):
        favicon = f'<link rel="icon" href="{favicon}">' if favicon else ""
        scripts = "\n".join([f'<script src="{i}"></script>' for i in scripts]) if scripts else ""
        stylesheets = "\n".join([f'<link rel="stylesheet" href="{i}">' for i in stylesheets]) if stylesheets else ""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    {favicon}
    {scripts}
    {stylesheets}
</head>
<body>
    {body}
</body>
</html>"""
        super().__init__(html, status_code, headers, version, raw=raw)


class HTMLTextResponse(StandardHTMLResponse): # this is easier to implement than escaping the text
    def __init__(self, body: str, title="", favicon=None,  scripts: list = None, stylesheets = None, status_code: int = 200, headers: dict = None, version: str = "HTTP/1.1", raw: bool = False):
        super().__init__(f"<pre>{body}</pre>",
                            title=title,
                            favicon=favicon,
                            scripts=scripts,
                            stylesheets=stylesheets,
                            status_code=status_code,
                            headers=headers,
                            version=version,
                         raw=raw)


class TBDBResponse(StandardHTMLResponse):
    """Displays tabular json data in a table using https://github.com/modularizer/teebydeeby"""
    def __init__(self, data, title="", favicon=None,  scripts: list = None, stylesheets = None, status_code: int = 200, headers: dict = None, version: str = "HTTP/1.1", raw: bool = False):
        if not isinstance(data, str):
            data = dumps(data, indent=4)
        super().__init__(f"<teeby-deeby>{data}</teeby-deeby>",
                            title=title,
                            favicon=favicon,
                            scripts=["https://cdnjs.cloudflare.com/ajax/libs/lz-string/1.4.4/lz-string.min.js", "https://modularizer.github.io/teebydeeby/tbdb.js"] + list(scripts or []),
                            stylesheets=stylesheets,
                            status_code=status_code,
                            headers=headers,
                            version=version,
                         raw=raw)

class JSONResponse(SuccessResponse):
    def __init__(self, data: str | dict | list | tuple | int | float, status_code: int = 200, headers: dict = None,
                 version: str = "HTTP/1.1", raw: bool = False):
        if headers is None:
            headers = {}
        headers = Headers(headers)
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        if not isinstance(data, str):
            if isinstance(data, tuple):
                data = list(data)
            if dataclasses and dataclasses.is_dataclass(data):
                data = dataclasses.asdict(data)

            if hasattr(data, "to_json"):
                try:
                    data = data.to_json()
                except:
                    if hasattr(data, "to_dict"):
                        try:
                            data = dumps(data.to_dict())
                        except:
                            data = str(data)
                    else:
                        data = str(data)
            elif hasattr(data, "to_dict"):
                try:
                    data = dumps(data.to_dict())
                except:
                    data = str(data)
            else:
                data = dumps(data)
        super().__init__(data.encode(), status_code, headers, version, raw=raw)


class ErrorResponse(ServerError):
    def __init__(self,
                 error: Exception = b'Internal Server Error',
                 status_code: int = 500,
                 headers: dict = None,
                 version: str = "HTTP/1.1", raw: bool = False):
        if headers is None:
            headers = {}
        if isinstance(error, Exception):
            error = str(error).encode()
        elif isinstance(error, bytes):
            pass
        else:
            error = str(error).encode()
        if "Content-Type" not in headers:
            headers["Content-Type"] = "text/plain"
        super().__init__(error, status_code, headers, version, raw=raw)


class RedirectResponse(RedirectionResponse):
    def __init__(self, location: str, status_code: int = 307, headers: dict = None, version: str = "HTTP/1.1", raw: bool = False):
        if headers is None:
            headers = {}
        if "Location" not in headers:
            headers["Location"] = location
        super().__init__(b"", status_code, headers, version, raw=raw)

    def __str__(self):
        return f"{self.__class__.__name__}({self.headers['Location']})"


class TemporaryRedirect(RedirectResponse):
    def __init__(self, location: str, status_code: int = 307, headers: dict = None, version: str = "HTTP/1.1", raw: bool = False):
        super().__init__(location, status_code, headers, version, raw=raw)


class PermanentRedirect(RedirectResponse):
    def __init__(self, location: str, status_code: int = 308, headers: dict = None, version: str = "HTTP/1.1", raw: bool = False):
        super().__init__(location, status_code, headers, version, raw=raw)


url_encodings = {
    " ": "%20",
    "!": "%21",
    '"': "%22",
    "#": "%23",
    "$": "%24",
    "%": "%25",
    "&": "%26",
    "'": "%27",
    "(": "%28",
    ")": "%29",
    "*": "%2A",
    "+": "%2B",
    ",": "%2C",
    "-": "%2D",
    ".": "%2E",
    "/": "%2F",
    "0": "%30",
    "1": "%31",
    "2": "%32",
    "3": "%33",
    "4": "%34",
    "5": "%35",
    "6": "%36",
    "7": "%37",
    "8": "%38",
    "9": "%39",
    ":": "%3A",
    ";": "%3B",
    "<": "%3C",
    "=": "%3D",
    ">": "%3E",
    "?": "%3F",
    "@": "%40",
    "A": "%41",
    "B": "%42",
    "C": "%43",
    "D": "%44",
    "E": "%45",
    "F": "%46",
    "G": "%47",
    "H": "%48",
    "I": "%49",
    "J": "%4A",
    "K": "%4B",
    "L": "%4C",
    "M": "%4D",
    "N": "%4E",
    "O": "%4F",
    "P": "%50",
    "Q": "%51",
    "R": "%52",
    "S": "%53",
    "T": "%54",
    "U": "%55",
    "V": "%56",
    "W": "%57",
    "X": "%58",
    "Y": "%59",
    "Z": "%5A",
    "[": "%5B",
    "\\": "%5C",
    "]": "%5D",
    "^": "%5E",
    "_": "%5F",
    "`": "%60",
    "a": "%61",
    "b": "%62",
    "c": "%63",
    "d": "%64",
    "e": "%65",
    "f": "%66",
    "g": "%67",
    "h": "%68",
    "i": "%69",
    "j": "%6A",
    "k": "%6B",
    "l": "%6C",
    "m": "%6D",
    "n": "%6E",
    "o": "%6F",
    "p": "%70",
    "q": "%71",
    "r": "%72",
    "s": "%73",
    "t": "%74",
    "u": "%75",
    "v": "%76",
    "w": "%77",
    "x": "%78",
    "y": "%79",
    "z": "%7A",
    "{": "%7B",
    "|": "%7C",
    "}": "%7D",
    "~": "%7E",
    "\x7F": "%7F",
    "€": "%E2%82%AC",
    "\x81": "%81",
    "‚": "%E2%80%9A",
    "ƒ": "%C6%92",
    "„": "%E2%80%9E",
    "…": "%E2%80%A6",
    "†": "%E2%80%A0",
    "‡": "%E2%80%A1",
    "ˆ": "%CB%86",
    "‰": "%E2%80%B0",
    "Š": "%C5%A0",
    "‹": "%E2%80%B9",
    "Œ": "%C5%92",
    "\x8D": "%C5%8D",
    "Ž": "%C5%BD",
    "\x8F": "%8F",
    "\x90": "%C2%90",
    "‘": "%E2%80%98",
    "’": "%E2%80%99",
    "“": "%E2%80%9C",
    "”": "%E2%80%9D",
    "•": "%E2%80%A2",
    "–": "%E2%80%93",
    "—": "%E2%80%94",
    "˜": "%CB%9C",
    "™": "%E2%84%A2",
    "š": "%C5%A1",
    "›": "%E2%80%BA",
    "œ": "%C5%93",
    "\x9D": "%9D",
    "ž": "%C5%BE",
    "Ÿ": "%C5%B8",
    "\xA0": "%C2%A0",
    "¡": "%C2%A1",
    "¢": "%C2%A2",
    "£": "%C2%A3",
    "¤": "%C2%A4",
    "¥": "%C2%A5",
    "¦": "%C2%A6",
    "§": "%C2%A7",
    "¨": "%C2%A8",
    "©": "%C2%A9",
    "ª": "%C2%AA",
    "«": "%C2%AB",
    "¬": "%C2%AC",
    "\xAD": "%C2%AD",
    "®": "%C2%AE",
    "¯": "%C2%AF",
    "°": "%C2%B0",
    "±": "%C2%B1",
    "²": "%C2%B2",
    "³": "%C2%B3",
    "´": "%C2%B4",
    "µ": "%C2%B5",
    "¶": "%C2%B6",
    "·": "%C2%B7",
    "¸": "%C2%B8",
    "¹": "%C2%B9",
    "º": "%C2%BA",
    "»": "%C2%BB",
    "¼": "%C2%BC",
    "½": "%C2%BD",
    "¾": "%C2%BE",
    "¿": "%C2%BF",
    "À": "%C3%80",
    "Á": "%C3%81",
    "Â": "%C3%82",
    "Ã": "%C3%83",
    "Ä": "%C3%84",
    "Å": "%C3%85",
    "Æ": "%C3%86",
    "Ç": "%C3%87",
    "È": "%C3%88",
    "É": "%C3%89",
    "Ê": "%C3%8A",
    "Ë": "%C3%8B",
    "Ì": "%C3%8C",
    "Í": "%C3%8D",
    "Î": "%C3%8E",
    "Ï": "%C3%8F",
    "Ð": "%C3%90",
    "Ñ": "%C3%91",
    "Ò": "%C3%92",
    "Ó": "%C3%93",
    "Ô": "%C3%94",
    "Õ": "%C3%95",
    "Ö": "%C3%96",
    "×": "%C3%97",
    "Ø": "%C3%98",
    "Ù": "%C3%99",
    "Ú": "%C3%9A",
    "Û": "%C3%9B",
    "Ü": "%C3%9C",
    "Ý": "%C3%9D",
    "Þ": "%C3%9E",
    "ß": "%C3%9F",
    "à": "%C3%A0",
    "á": "%C3%A1",
    "â": "%C3%A2",
    "ã": "%C3%A3",
    "ä": "%C3%A4",
    "å": "%C3%A5",
    "æ": "%C3%A6",
    "ç": "%C3%A7",
    "è": "%C3%A8",
    "é": "%C3%A9",
    "ê": "%C3%AA",
    "ë": "%C3%AB",
    "ì": "%C3%AC",
    "í": "%C3%AD",
    "î": "%C3%AE",
    "ï": "%C3%AF",
    "ð": "%C3%B0",
    "ñ": "%C3%B1",
    "ò": "%C3%B2",
    "ó": "%C3%B3",
    "ô": "%C3%B4",
    "õ": "%C3%B5",
    "ö": "%C3%B6",
    "÷": "%C3%B7",
    "ø": "%C3%B8",
    "ù": "%C3%B9",
    "ú": "%C3%BA",
    "û": "%C3%BB",
    "ü": "%C3%BC",
    "ý": "%C3%BD",
    "þ": "%C3%BE",
    "ÿ": "%C3%BF"
}


def url_encode(s: str, is_query=False) -> str:
    if is_query:
        extra_encodings = {" ": "+", "&": "%26", "=": "%3D"}
        for k, e in extra_encodings.items():
            s = s.replace(k, e)
    for k, e in url_encodings.items():
        s = s.replace(k, e)
    return s


def url_encode_query(s: str) -> str:
    return url_encode(s, True)


def url_decode(s: str, is_query=False) -> str:
    for e, k in url_encodings.items():
        s = s.replace(k, e)
    if is_query:
        extra_decodings = {"+": " "}
        for k, e in extra_decodings.items():
            s = s.replace(k, e)
    return s

def url_decode_query(s: str) -> str:
    return url_decode(s, True)


class Query(dict):
    def __str__(self):
        return "?" + "&".join([f"{url_encode(k)}={url_encode(v)}" for k, v in self.items()])


class Route(str):
    pass


class FullPath(str):
    pass


class Method(str):
    pass



class ErrorModes:
    HIDE = "hide"
    TYPE = "type"
    SHORT = "short"
    TRACEBACK = TB = LONG = SHOW = "traceback"

    DEFAULT = TRACEBACK


def set_default_error_mode(mode: str):
    if mode not in [ErrorModes.HIDE, ErrorModes.TYPE, ErrorModes.SHORT, ErrorModes.TRACEBACK]:
        raise ValueError(f"Invalid error mode: {mode}. Options are 'hide', 'type', 'short', 'traceback'.")
    ErrorModes.DEFAULT = mode

