class TemporaryFile:
    def __init__(self, mode='w+b'):
        self.file = bytes()
        self.cursor = 0
        self.mode = mode

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def write(self, data):
        at_end = self.cursor == len(self.file)
        if at_end:
            if "w" not in self.mode and "a" not in self.mode:
                raise ValueError("File not open for writing")

            if 'b' in self.mode:
                self.file += bytes(data, 'utf-8')
            else:
                self.file += data.decode('utf-8')
        else:
            if "w" not in self.mode:
                raise ValueError("File not open for writing")
            if 'b' in self.mode:
                data = bytes(data, 'utf-8')
            else:
                data = data.encode('utf-8')
            self.file = self.file[:self.cursor] + data + self.file[self.cursor + len(data):]
        self.cursor += len(data)

    def read(self, size=-1):
        if "r" not in self.mode:
            raise ValueError("File not open for reading")
        return self.file[self.cursor:] if size == -1 else self.file[self.cursor:self.cursor + size]

    def seek(self, offset, whence=0):
        if whence == 0:
            self.cursor = offset
        elif whence == 1:
            self.cursor += offset
        elif whence == 2:
            self.cursor = len(self.file) + offset
        else:
            raise ValueError("Invalid whence value")
