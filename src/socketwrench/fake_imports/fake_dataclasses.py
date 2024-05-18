class dataclasses:
    def is_dataclass(obj):
        return False

    def as_dict(obj):
        return obj.__dict__
