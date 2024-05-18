from socketwrench.server import Server


def main():
    from socketwrench.standardlib_dependencies import ArgumentParser
    parser = ArgumentParser(description="Serve a module or class.")
    parser.add_argument("module_or_class", help="The module or class to serve.")
    # add help text for the other arguments
    parser.add_argument("--host", help="The host to bind to.", default="*", type=str)
    parser.add_argument("--port", help="The port to bind to.", default=8080, type=int)
    parser.add_argument("--errors", help="The error mode to use.", default="hide", type=str, choices=["hide", "short", "show", "tb","traceback"])

    args = parser.parse_args()
    Server.serve(args.module_or_class, host=args.host, port=args.port, error_mode=args.errors)


if __name__ == '__main__':
    from socketwrench.standardlib_dependencies import argv
    if len(argv) != 2:
        print("Usage: python -m socketwrench <import.path.of.module.or.class>")
        print("Example: python -m socketwrench socketwrench.samples.sample.Sample")
        print(f"Sample Shortcut: python -m socketwrench sample")
        exit(1)
    m = argv[1]
    if m == "sample":
        m = "socketwrench.samples.sample.Sample"
    Server.serve(m)
