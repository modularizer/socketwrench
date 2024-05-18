

def dumps(obj, indent=None):
    if isinstance(obj, (int, float)):
        return str(obj)
    elif obj is None:
        return "null"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif isinstance(obj, str):
        return f'"{obj}"'
    elif isinstance(obj, list):
        s = "[" + ", ".join(dumps(x) for x in obj) + "]"
        if indent:
            return s.replace(", ", ",\n" + " " * indent)
        return s
    elif isinstance(obj, dict):
        s = "{" + ", ".join(f'"{k}": {dumps(v)}' for k, v in obj.items()) + "}"
        if indent:
            return s.replace(", ", ",\n" + " " * indent)
        return s
    else:
        raise TypeError(f"Cannot serialize {type(obj)}")


def loads(s):
    if not isinstance(s, str):
        return s
    if s == "null":
        return None
    elif s == "true":
        return True
    elif s == "false":
        return False
    elif s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    elif s[0] == "[" and s[-1] == "]":
        # iterate through and split on commas, but only if the comma is not inside a string
        a = []
        in_string = False
        escaped = False
        last_index = 0
        for i, c in enumerate(s):
            if c == '"' and not escaped:
                in_string = not in_string
            elif c == "\\":
                escaped = True
            elif c == "," and not in_string:
                a.append(s[last_index:i])
                last_index = i + 1
            if escaped:
                escaped = False
        a.append(s[last_index:])
        return [loads(x) for x in a]
    elif s[0] == "{" and s[-1] == "}":
        # iterate through and split on commas, but only if the comma is not inside a string
        kv = []
        in_string = False
        escaped = False
        last_index = 0
        for i, c in enumerate(s):
            if c == '"' and not escaped:
                in_string = not in_string
            elif c == "\\":
                escaped = True
            elif c == "," and not in_string:
                kv.append(s[last_index:i])
                last_index = i + 1
            if escaped:
                escaped = False
        kv.append(s[last_index:])
        d = {loads(x.split(":")[0]): loads(x.split(":")[1].trim()) for x in kv}
        return d
    else:
        try:
            return int(s)
        except ValueError:
            try:
                return float(s)
            except ValueError:
                return s