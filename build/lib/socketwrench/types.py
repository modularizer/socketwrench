import json
from pathlib import Path


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

class Body(bytes):
    EMPTY = b""

class RequestBody(Body):
    pass


class Headers(dict):
    EMPTY = {}

    def to_string(self) -> str:
        s = ""
        for k, v in self.items():
            s += f"{k}: {v}\n"
        return s

    def __str__(self):
        return self.to_string()

    def to_bytes(self) -> bytes:
        return self.to_string().encode()


class HeaderBytes(bytes):
    EMPTY = b""

    def __new__(cls, s: bytes | Headers | dict[str, str]):
        if isinstance(s, Headers):
            s = s.to_bytes()
        elif isinstance(s, dict):
            s = Headers(s).to_bytes()
        return super().__new__(cls, s)

    def to_string(self):
        return self.decode()

    def to_dict(self) -> dict:
        lines = self.decode().splitlines()
        items = [v.split(":", 1) for v in lines]
        d = {k.strip(): v.strip() for k, v in items}
        return Headers(d)

    def __iter__(self):
        return iter(self.to_dict())


class RequestPath(str):
    EMPTY = ""
    BASE = "/"

    def query(self) -> str:
        """Extracts the query string from the path and remove the hash."""
        if "?" not in self:
            return ""
        q = self.split("?", 1)[1]
        if "#" in q:
            q = q.split("#", 1)[0]
        return q

    def route(self) -> str:
        """Extracts the path from the path and remove the query and hash."""
        p = self.split("?", 1)[0]
        if "#" in p:
            p = p.split("#", 1)[0]
        return p

    def hash(self) -> str:
        """Extracts the hash from the path."""
        if "#" not in self:
            return ""
        return self.split("#", 1)[1]

    def query_args(self) -> dict[str, str]:
        """Extracts the query string from the path and remove the hash."""
        q = self.query()
        if not q:
            return {}
        items = [v.split("=", 1) for v in q.split("&")]
        d = {k: v for k, v in items}
        return d


class ClientAddr(str):
    def __new__(cls, host_port: str | tuple[str, int]):
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
    def from_components(cls, pre_body_bytes: bytes, body: bytes, client_addr: str | tuple[str, int]) -> "Request":
        """Create a Request object from a header string and a body bytes object."""
        i = pre_body_bytes.index(b"\r\n")
        first_line = pre_body_bytes[:i].decode()
        method, path, version = first_line.split(" ")
        header_bytes = pre_body_bytes[i + 2:]
        return cls(method, path, version, header_bytes, body, client_addr)

    def __init__(self,
                 method: str | HTTPMethod = HTTPMethod.GET,
                 path: str | RequestPath = RequestPath.BASE,
                 version: str | HTTPVersion = HTTPVersion.HTTP_1_1,
                 header: bytes | HeaderBytes | Headers | dict[str, str] = HeaderBytes.EMPTY,
                 body: bytes | RequestBody = RequestBody.EMPTY,
                 client_addr: str | tuple[str, int] | None = None,
                 ):
        self.method = HTTPMethod(method)
        self.path = RequestPath(path)
        self.version = HTTPVersion(version)
        self.header_bytes = HeaderBytes(header)
        self._headers = None
        self.body = RequestBody(body)
        self.client_addr = ClientAddr(client_addr) if client_addr else None

    @property
    def headers(self) -> Headers:
        if self._headers is None:
            self._headers = Headers(self.header_bytes)
        return self._headers

    def __repr__(self):
        return f"<Request {self.method} {self.path} client_addr={self.client_addr} ...>"


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

    def __new__(cls, status_code: int, phrase: str | None = None):
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


for k, v in HTTPStatusCode.__dict__.items():
    if isinstance(v, int):
        setattr(HTTPStatusCode, k, HTTPStatusCode(v, k.replace("_", " ")))


class Response:
    def __new__(cls, body: bytes | ResponseBody = ResponseBody.EMPTY,
                status_code: int | HTTPStatusCode = HTTPStatusCode.OK,
                headers: bytes | HeaderBytes | Headers | dict = HeaderBytes.EMPTY,
                version: str | HTTPVersion = HTTPVersion.HTTP_1_1,
                **headers_kwargs):

        # If the body is already a Response instance, return it
        if isinstance(body, Response):
            return body

        # Create an instance of the appropriate subclass based on the body type
        if isinstance(body, (bytes, memoryview)):
            return super(Response, cls).__new__(cls)
        elif isinstance(body, str) and not issubclass(cls, HTMLResponse):
            return super(Response, HTMLResponse).__new__(HTMLResponse)
        elif isinstance(body, Path) and not issubclass(cls, FileResponse):
            return super(Response, FileResponse).__new__(FileResponse)
        elif isinstance(body, Exception) and not issubclass(cls, ErrorResponse):
            return super(Response, ErrorResponse).__new__(ErrorResponse)
        else:
            if not issubclass(cls, JSONResponse):
                return super(Response, JSONResponse).__new__(JSONResponse)
            else:
                return super(Response, cls).__new__(cls)

    def __init__(self,
                 body: bytes | ResponseBody = ResponseBody.EMPTY,
                 status_code: int | HTTPStatusCode = HTTPStatusCode.OK,
                 headers: bytes | HeaderBytes | Headers | dict = HeaderBytes.EMPTY,
                 version: str | HTTPVersion = HTTPVersion.HTTP_1_1,
                 **headers_kwargs
                 ):
        self.status_code = HTTPStatusCode(status_code)
        self.version = HTTPVersion(version)
        self.headers = HeaderBytes(headers)
        for k, v in headers_kwargs.items():
            t = k.replace("_", " ").title().replace(" ", "-")
            if not isinstance(v, str):
                v = json.dumps(v)
            self.headers[t] = v
        self.body = ResponseBody(body)

    def pre_body_bytes(self) -> bytes:
        return f'{self.version} {self.status_code}\r\n{self.headers}\r\n\r\n'.encode()

    def __repr__(self):
        return f"<Response {self.status_code} {self.body[:10]}>"

    def __bytes__(self):
        return self.pre_body_bytes() + self.body

    def __buffer__(self, flags):
        return memoryview(bytes(self))


class FileResponse(Response):
    def __init__(self,
                 path: str | Path,
                 filename: str | None = None,
                 status_code: int = 200,
                 headers: dict = None,
                 content_type: str | None = None,
                 version: str = "HTTP/1.1"):
        path = Path(path)
        if filename is None:
            filename = path.name

        if headers is None:
            headers = {}

        if "Content-Disposition" not in headers:
            headers["Content-Disposition"] = f'attachment; filename="{filename}"'

        # add headers related to file stats
        if "Content-Length" not in headers:
            headers["Content-Length"] = str(path.stat().st_size)
        if "Last-Modified" not in headers:
            headers["Last-Modified"] = path.stat().st_mtime

        if path.is_dir():
            from tempfile import TemporaryFile
            from zipfile import ZipFile
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
        else:
            if content_type is None:
                content_type = self.get_content_type(path.suffix[1:])

            super().__init__(path.read_bytes(),
                             status_code=status_code,
                             headers=headers,
                             content_type=content_type,
                             version=version)

    def get_content_type(self, suffix: str):
        suffix = suffix.lower()
        if suffix == "html":
            return "text/html"
        elif suffix == "css":
            return "text/css"
        elif suffix == "js":
            return "application/javascript"
        elif suffix == "png":
            return "image/png"
        elif suffix == "jpg" or suffix == "jpeg":
            return "image/jpeg"
        elif suffix == "gif":
            return "image/gif"
        elif suffix == "svg":
            return "image/svg+xml"
        elif suffix == "ico":
            return "image/x-icon"
        elif suffix == "json":
            return "application/json"
        elif suffix == "yml" or suffix == "yaml":
            return "application/x-yaml"
        elif suffix == "doc":
            return "application/msword"
        elif suffix == "docx":
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        elif suffix == "xls":
            return "application/vnd.ms-excel"
        elif suffix == "xlsx":
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        elif suffix == "ppt":
            return "application/vnd.ms-powerpoint"
        elif suffix == "pptx":
            return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        elif suffix == "odt":
            return "application/vnd.oasis.opendocument.text"
        elif suffix == "ods":
            return "application/vnd.oasis.opendocument.spreadsheet"
        elif suffix == "odp":
            return "application/vnd.oasis.opendocument.presentation"
        elif suffix == "odg":
            return "application/vnd.oasis.opendocument.graphics"
        elif suffix == "odf":
            return "application/vnd.oasis.opendocument.formula"
        elif suffix == "pdf":
            return "application/pdf"
        elif suffix == "zip":
            return "application/zip"
        elif suffix == "tar":
            return "application/x-tar"
        elif suffix == "gz":
            return "application/gzip"
        elif suffix == "mp3":
            return "audio/mpeg"
        elif suffix == "mp4":
            return "video/mp4"
        elif suffix == "webm":
            return "video/webm"
        elif suffix == "ogg":
            return "audio/ogg"
        elif suffix == "wav":
            return "audio/wav"
        elif suffix == "txt":
            return "text/plain"
        elif suffix == "csv":
            return "text/csv"
        elif suffix == "xml":
            return "text/xml"
        elif suffix == "md":
            return "text/markdown"
        elif suffix == "py":
            return "text/x-python"
        elif suffix == "c":
            return "text/x-c"
        elif suffix == "cpp":
            return "text/x-c++"
        elif suffix == "h":
            return "text/x-c-header"
        elif suffix == "hs":
            return "text/x-haskell"
        elif suffix == "java":
            return "text/x-java"
        elif suffix == "sh":
            return "text/x-shellscript"
        elif suffix == "bat":
            return "text/x-batch"
        elif suffix == "ps1":
            return "text/x-powershell"
        elif suffix == "rb":
            return "text/x-ruby"
        elif suffix == "rs":
            return "text/x-rust"
        elif suffix == "go":
            return "text/x-go"
        elif suffix == "php":
            return "text/x-php"
        elif suffix == "pl":
            return "text/x-perl"
        elif suffix == "swift":
            return "text/x-swift"
        elif suffix == "asm":
            return "text/x-asm"
        elif suffix == "bat":
            return "text/x-batch"
        else:
            return "application/octet-stream"


class HTMLResponse(Response):
    def __init__(self, html: str, status_code: int = 200, headers: dict = None, version: str = "HTTP/1.1"):
        if headers is None:
            headers = {}
        if "Content-Type" not in headers:
            headers["Content-Type"] = "text/html"
        super().__init__(html.encode(), status_code, headers, version)


class JSONResponse(Response):
    def __init__(self, data: str | dict | list | tuple | int | float, status_code: int = 200, headers: dict = None,
                 version: str = "HTTP/1.1"):
        if headers is None:
            headers = {}
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        if not isinstance(data, str):
            if isinstance(data, tuple):
                data = list(data)
            data = json.dumps(data)
        super().__init__(data.encode(), status_code, headers, version)


class ErrorResponse(Response):
    def __init__(self,
                 error: str | bytes | Exception = b'Internal Server Error',
                 status_code: int = 500,
                 headers: dict = None,
                 version: str = "HTTP/1.1"):
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
        super().__init__(error, status_code, headers, version)

class RedirectResponse(Response):
    def __init__(self, location: str, status_code: int = 307, headers: dict = None, version: str = "HTTP/1.1"):
        if headers is None:
            headers = {}
        if "Location" not in headers:
            headers["Location"] = location
        super().__init__(b"", status_code, headers, version)


class TemporaryRedirect(RedirectResponse):
    def __init__(self, location: str, status_code: int = 307, headers: dict = None, version: str = "HTTP/1.1"):
        super().__init__(location, status_code, headers, version)


class PermanentRedirect(RedirectResponse):
    def __init__(self, location: str, status_code: int = 308, headers: dict = None, version: str = "HTTP/1.1"):
        super().__init__(location, status_code, headers, version)


class Query(dict):
    pass

class Hash(str):
    pass

class Route(str):
    pass

class FullPath(str):
    pass

class Method(str):
    pass

class File(bytes):
    pass
