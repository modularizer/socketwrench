
def format_exception(t, e, tb):
    print(f"making fake traceback for {t.__name__}: {e}")
    return [f"{t.__name__}: {e}"] + (tb if isinstance(tb, list) else [])