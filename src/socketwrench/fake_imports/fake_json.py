

def dumps(obj, indent=None):
    if isinstance(obj, bool):
        s = "true" if obj else "false"
    elif isinstance(obj, (int, float)):
        s = str(obj)
    elif obj is None:
        s = "null"
    elif isinstance(obj, str):
        s = f'"{obj}"'
    elif isinstance(obj, list):
        s = "[" + ", ".join(dumps(x) for x in obj) + "]"
        if indent:
            s = s.replace(", ", ",\n" + " " * indent)
    elif isinstance(obj, dict):
        s = "{" + ", ".join(f'"{k}": {dumps(v)}' for k, v in obj.items()) + "}"
        if indent:
            s = s.replace(", ", ",\n" + " " * indent)
    else:
        raise TypeError(f"Cannot serialize {type(obj)}")
    print()
    return s


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