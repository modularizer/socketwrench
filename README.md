# socketwrench
A webserver based on `socket`.

## Usage
```python
import logging
from socketwrench import Server as SocketWrench
from pathlib import Path

logging.basicConfig(level=logging.DEBUG)

class Sample:
    def a(self):
        return "yes this is a"

    def b(self):
        return {"x": 6, "y": 7}

    def c(self):
        return Path(__file__)

    def d(self, x: int, y: int):
        return int(x) + int(y)

    def e(self):
        raise Exception("This is an exception")

s = Sample()

SocketWrench(s, serve=True)
```