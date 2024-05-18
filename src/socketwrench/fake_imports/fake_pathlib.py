class Path:
    def __init__(self, path):
        self.path = str(path)

    def __str__(self):
        return self.path

    def __repr__(self):
        return self.path

    def __fspath__(self):
        return self.path

    def resolve(self):
        return self.path

    def __truediv__(self, other):
        slash_count = self.path.count("/")
        backslash_count = self.path.count("\\")
        other_slash_count = other.count("/")
        other_backslash_count = other.count("\\")
        slash = '/' if (slash_count + other_slash_count) > (backslash_count + other_backslash_count) else '\\'
        return Path(self.path + slash + other)

    @property
    def slash(self):
        return "/" if self.path.count("/") > self.path.count("\\") else "\\"

    @property
    def parent(self):
        return Path("/".join(self.path.split(self.slash)[:-1]))

    @property
    def name(self):
        return self.path.split(self.slash)[-1]

    @property
    def parts(self):
        return self.path.split(self.slash)

    @property
    def stem(self):
        return self.path.split(self.slash)[-1].split(".")[0]

    @property
    def suffix(self):
        return "." + self.path.split(self.slash)[-1].split(".")[1]

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

    def stat(self):
        return Stat(self.path)

class Stat:
    def __init__(self, path):
        self.path = path

    @property
    def st_size(self):
        with open(self.path, "rb") as f:
            return len(f.read())

    @property
    def st_mtime(self):
        return 0

