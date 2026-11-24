import json


def logql_string(value) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def unescape_value(value):
    if not isinstance(value, str) or "\\" not in value:
        return value
    try:
        return json.loads(f'"{value}"')
    except ValueError:
        return value
