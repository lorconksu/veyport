"""Shared integrity assertions for offline authenticated-context test fixtures."""
import copy


def change_context_fields(test, state, changes):
    """Copy the selected branches and prove every other authority input is intact."""
    def leaves(value, path=()):
        if isinstance(value, dict):
            return {key: leaf for name, item in value.items()
                    for key, leaf in leaves(item, path+(name,)).items()}
        return {path: value}
    expected = copy.deepcopy(leaves(state))
    for path, value in changes:
        parent = state
        for key in path[:-1]:
            parent[key] = copy.deepcopy(parent[key])
            parent = parent[key]
        parent[path[-1]] = copy.deepcopy(value)
        expected[path] = value
    test.assertEqual(leaves(state), expected)
