class Path:
    def __init__(self, path):
        self.path = path

    def __str__(self):
        return self.path

    def __repr__(self):
        return self.path

    def __fspath__(self):
        return self.path

    def resolve(self):
        return self.path

    def __truediv__(self, other):
        return Path(self.path + "/" + other)

    @property
    def parent(self):
        return Path("/".join(self.path.split("/")[:-1]))

    @property
    def name(self):
        return self.path.split("/")[-1]

    @property
    def parts(self):
        return self.path.split("/")

    @property
    def stem(self):
        return self.path.split("/")[-1].split(".")[0]

    @property
    def suffix(self):
        return self.path.split("/")[-1].split(".")[1]

    def exists(self):
        try:
            with open(self.path) as f:
                return True
        except:
            return False

    def open(self, mode="r"):
        return open(self.path, mode)

    def is_dir(self):
        try:
            return len(self.path.split(".")) == 1
        except:
            return False

    def iterdir(self):
        try:
            import os
            if self.is_dir():
                return [Path(f) for f in os.listdir(self.path)]
        except:
            pass
        return []