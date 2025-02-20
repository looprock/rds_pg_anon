from typing import Any

def has_circular_reference(obj, seen=None):
    # check if the object has a circular reference
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return True
    seen.add(obj_id)
    if isinstance(obj, dict):
        print(f"Checking dict: {obj}")  # Log the dict being checked
        return any(has_circular_reference(v, seen) for v in obj.values())
    elif isinstance(obj, list):
        print(f"Checking list: {obj}")  # Log the list being checked
        return any(has_circular_reference(i, seen) for i in obj)
    return False

def default_serializer(obj: Any) -> str:
    """JSON serializer for objects not serializable by default json code"""
    if hasattr(obj, 'name'):
        if hasattr(obj, 'table'):
            return f"{obj.table.name}.{obj.name}"
        return str(obj.name)
    if hasattr(obj, 'target'):
        if hasattr(obj, 'parent'):
            return f"{obj.parent.name}->{obj.target.name}"
        return str(obj.target.name)
    return str(obj)