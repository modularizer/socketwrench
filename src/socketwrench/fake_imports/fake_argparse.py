"""
parser = ArgumentParser(description="Serve a module or class.")
    parser.add_argument("module_or_class", help="The module or class to serve.")
    # add help text for the other arguments
    parser.add_argument("--host", help="The host to bind to.", default="*", type=str)
    parser.add_argument("--port", help="The port to bind to.", default=8080, type=int)
    parser.add_argument("--errors", help="The error mode to use.", default="hide", type=str, choices=["hide", "short", "show", "tb","traceback"])

    args = parser.parse_args()
    Server.serve(args.module_or_class, host=args.host, port=args.port, error_mode=args.errors)
"""


class Namespace(dict):
    def __getattr__(self, name):
        return self[name]

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        del self[name]

    def __repr__(self):
        return f"Namespace({super().__repr__()})"

    def __str__(self):
        return f"Namespace({super().__str__()})"

class NoDefault:
    pass

class ArgumentParser:
    def __init__(self, description):
        self.description = description
        self.pos_args = []
        self.kw_args = {}

    def add_argument(self, name, help, default=NoDefault, type=None, choices=None, action=None):
        info = {
            "name": name,
            "help": help,
            "default": default,
            "type": type,
            "choices": choices,
            "action": action
        }
        if name.startswith("--"):
            self.kw_args[name[2:]] = info
        else:
            self.pos_args.append(info)

    def parse_args(self, args=None):
        if args is None:
            try:
                from sys import argv
            except ImportError:
                argv = []
            args = argv[1:]

        if "--help" in args or "-h" in args:
            print(self.description)
            print("Positional arguments:")
            for info in self.pos_args:
                print(f"  {info['name']}: {info['help']}")
            print("Keyword arguments:")
            for kw, info in self.kw_args.items():
                print(f"  --{kw}: {info['help']}")
            exit(0)

        n = Namespace()
        for kw, info in self.kw_args.items():
            if info["default"] is not NoDefault:
                n[kw] = info["default"]
            elif info["action"] == "store_true":
                n[kw] = False
            elif info["action"] == "store_false":
                n[kw] = True

        goes_with = None
        for i, arg in enumerate(args):
            if arg.startswith("--"):
                if goes_with is not None:
                    info = self.kw_args[goes_with]
                    if info["action"] == "store_true":
                        n[goes_with] = True
                    elif info["action"] == "store_false":
                        n[goes_with] = False
                    else:
                        raise ValueError(f"No value provided for {goes_with}")
                    goes_with = None
                arg = arg[2:]
                if "=" in arg:
                    name, value = arg.split("=", 1)
                    info = self.kw_args[name]
                    if info["type"] is not None:
                        value = info["type"](value)
                    if info["choices"] is not None:
                        if value not in info["choices"]:
                            raise ValueError(f"Invalid value for {name}: {value}")
                    n[name] = value
                else:
                    goes_with = arg
            else:
                if goes_with is not None:
                    info = self.kw_args[goes_with]
                    value = arg
                    if info["type"] is not None:
                        value = info["type"](value)
                    if info["choices"] is not None:
                        if value not in info["choices"]:
                            raise ValueError(f"Invalid value for {name}: {value}")
                    n[goes_with] = value
                    goes_with = None
                    continue
                elif i < len(self.pos_args):
                    info = self.pos_args[i]
                    if info["type"] is not None:
                        arg = info["type"](arg)
                    if info["choices"] is not None:
                        if arg not in info["choices"]:
                            raise ValueError(f"Invalid value for {info['name']}: {arg}")
                    n[info["name"]] = arg
                else:
                    raise ValueError(f"Too many positional arguments")

        if goes_with is not None:
            info = self.kw_args[goes_with]
            if info["action"] == "store_true":
                n[goes_with] = True
            elif info["action"] == "store_false":
                n[goes_with] = False
            else:
                raise ValueError(f"No value provided for {goes_with}")
        return n
