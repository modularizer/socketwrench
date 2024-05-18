class _empty:
    pass


class Parameter:
    VAR_POSITIONAL = 2
    VAR_KEYWORD = 4
    empty = _empty

    def __init__(self, name, kind, default=_empty, annotation=_empty):
        self.name = name
        self.kind = kind
        self.default = default
        self.annotation = annotation


class Signature:
    def __init__(self, parameters, return_annotation=_empty):
        self.parameters = parameters
        self.return_annotation = return_annotation


class inspect:
    Parameter = Parameter

    @staticmethod
    def signature(func):
        if not callable(func):
            raise TypeError(f"{func} is not a callable function")

        code = func.__code__
        varnames = code.co_varnames
        argcount = code.co_argcount
        defaults = func.__defaults__ or ()
        kwdefaults = func.__kwdefaults__ or {}

        parameters = []

        # Process positional arguments
        for i, varname in enumerate(varnames[:argcount]):
            kind = Parameter.POSITIONAL_OR_KEYWORD
            default = Parameter.empty
            if i >= argcount - len(defaults):
                default = defaults[i - (argcount - len(defaults))]
            param = Parameter(name=varname, kind=kind, default=default)
            parameters.append(param)

        # Add keyword-only arguments
        for varname in kwdefaults:
            kind = Parameter.KEYWORD_ONLY
            default = kwdefaults[varname]
            param = Parameter(name=varname, kind=kind, default=default)
            parameters.append(param)

        return Signature(parameters)

    @staticmethod
    def getsourcelines(obj):
        return ["# Source code not available\n"], 0

    @staticmethod
    def isfunction(obj):
        try:
            from types import FunctionType
            return isinstance(object, FunctionType)
        except ImportError:
            return callable(obj) and str(type(obj)) in ["<class 'function'>", "<class 'method'>"]


