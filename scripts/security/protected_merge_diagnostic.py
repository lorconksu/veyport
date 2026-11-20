"""Fixed GraphQL query and safe bypass-visibility observations for the fixture."""
import re

MAX_ACTORS = 100
GRAPHQL_INT_MAX = 2**31 - 1
GRAPHQL_QUERY = """
query SettingsVisibility($id: Int!) {
  repository(owner: "lorconksu", name: "veyport") {
    databaseId
    nameWithOwner
    ruleset(databaseId: $id) {
      databaseId
      bypassActors(first: 100) {
        totalCount
        pageInfo { hasNextPage hasPreviousPage }
        nodes {
          actor {
            __typename
            ... on App { databaseId }
            ... on User { id }
            ... on Team { id }
            ... on EnterpriseTeam { id }
          }
          bypassMode
          deployKey
          organizationAdmin
          enterpriseOwner
          enterpriseRole
          enterpriseRoleDatabaseId
          repositoryRoleDatabaseId
          repositoryRoleName
        }
      }
    }
  }
}
"""

_FLAGS = ('deployKey', 'organizationAdmin', 'enterpriseOwner', 'enterpriseRole')
_ROLE_FIELDS = ('enterpriseRoleDatabaseId', 'repositoryRoleDatabaseId', 'repositoryRoleName')


def _field(parent, key, expected_type):
    value = parent.get(key)
    if value is None:
        return ('null' if key in parent else 'missing'), None
    return ('visible', value) if type(value) is expected_type else ('malformed', None)


def _positive_id(value, maximum=GRAPHQL_INT_MAX):
    return type(value) is int and 0 < value <= maximum


def _rest_actor(row):
    if row is None:
        return 'incomplete'
    if type(row) is not dict or set(row) != {'actor_id', 'actor_type', 'bypass_mode'}:
        return 'malformed'
    if row['bypass_mode'] not in ('always', 'pull_request', 'exempt'):
        return 'malformed'
    kind, identity = row['actor_type'], row['actor_id']
    if kind in ('DeployKey', 'OrganizationAdmin'):
        valid = identity is None or (kind == 'OrganizationAdmin' and _positive_id(identity, 2**63-1))
        return 'visible' if valid else 'malformed'
    if kind not in ('Integration', 'RepositoryRole', 'Team', 'User'):
        return 'malformed'
    if identity is None:
        return 'incomplete'
    return 'visible' if _positive_id(identity, 2**63-1) else 'malformed'


def rest_bypass(rule, app_id):
    state, rows = _field(rule, 'bypass_actors', list)
    if state != 'visible':
        return {'roster': state, 'sole_app_pr_only': False}
    if len(rows) > MAX_ACTORS:
        return {'roster': 'limit-exceeded', 'sole_app_pr_only': False}
    for row in rows:
        state = _rest_actor(row)
        if state != 'visible':
            return {'roster': state, 'sole_app_pr_only': False}
    expected = {'actor_id': app_id, 'actor_type': 'Integration', 'bypass_mode': 'pull_request'}
    return {'roster': 'visible', 'sole_app_pr_only': rows == [expected]}


def _identity(parent, key, expected_id, expected_name=None):
    state, value = _field(parent, key, dict)
    if state != 'visible':
        return state, None
    identity = value.get('databaseId')
    if identity is None:
        return ('null' if 'databaseId' in value else 'missing'), None
    if not _positive_id(identity):
        return 'malformed', None
    if identity != expected_id:
        return 'mismatch', None
    if expected_name is not None:
        state, name = _field(value, 'nameWithOwner', str)
        if state != 'visible':
            return state, None
        if name != expected_name:
            return 'mismatch', None
    return 'verified', value


def _graphql_actor(row, app_id):
    if row is None:
        return 'incomplete', False
    if type(row) is not dict:
        return 'malformed', False
    if any(key not in row for key in ('actor', 'bypassMode', *_FLAGS, *_ROLE_FIELDS)) or row['bypassMode'] is None:
        return 'incomplete', False
    if (row['bypassMode'] not in ('ALWAYS', 'EXEMPT', 'PULL_REQUEST')
            or any(type(row[key]) is not bool for key in _FLAGS)):
        return 'malformed', False

    enterprise_id, repository_id, role_name = (row[key] for key in _ROLE_FIELDS)
    if enterprise_id is not None and (not row['enterpriseRole'] or type(enterprise_id) is not str
                                      or re.fullmatch(r'[1-9][0-9]{0,19}', enterprise_id) is None):
        return 'malformed', False
    if repository_id is not None and not _positive_id(repository_id):
        return 'malformed', False
    if role_name is not None and (repository_id is None or type(role_name) is not str or not role_name):
        return 'malformed', False
    special = sum(row[key] for key in _FLAGS) + (repository_id is not None)
    actor = row['actor']
    if special > 1 or (special and actor is not None):
        return 'malformed', False
    if actor is None:
        # A null actor alone can mean redaction. Recognize only explicit role or deploy-key rows.
        identified_role = special == 1 and (not row['enterpriseRole'] or enterprise_id is not None)
        return ('visible' if identified_role else 'incomplete'), False

    if type(actor) is not dict:
        return 'malformed', False
    kind = actor.get('__typename')
    if kind is None:
        return 'incomplete', False
    if kind == 'App':
        actual_id = actor.get('databaseId')
        if actual_id is None:
            return 'incomplete', False
        if not _positive_id(actual_id):
            return 'malformed', False
        return 'visible', actual_id == app_id and row['bypassMode'] == 'PULL_REQUEST'
    if kind not in ('User', 'Team', 'EnterpriseTeam'):
        return 'malformed', False
    actor_id = actor.get('id')
    if actor_id is None:
        return 'incomplete', False
    return ('visible' if type(actor_id) is str and 0 < len(actor_id) <= 256 else 'malformed'), False


def _graphql_roster(rule, app_id):
    state, bypass = _field(rule, 'bypassActors', dict)
    if state != 'visible':
        return state, False
    page_state, page = _field(bypass, 'pageInfo', dict)
    nodes_state, nodes = _field(bypass, 'nodes', list)
    count = bypass.get('totalCount')
    if (page_state == 'malformed' or nodes_state == 'malformed'
            or (count is not None and (type(count) is not int or count < 0))):
        return 'malformed', False
    if (count is not None and count > MAX_ACTORS) or (nodes is not None and len(nodes) > MAX_ACTORS):
        return 'limit-exceeded', False
    if page is None or nodes is None or count is None:
        return 'incomplete', False
    previous, following = page.get('hasPreviousPage'), page.get('hasNextPage')
    if previous is None or following is None:
        return 'incomplete', False
    if type(previous) is not bool or type(following) is not bool:
        return 'malformed', False
    if previous or following or len(nodes) != count:
        return 'incomplete', False
    sole_app = False
    for node in nodes:
        state, expected_app = _graphql_actor(node, app_id)
        if state != 'visible':
            return state, False
        sole_app = count == 1 and expected_app
    return 'visible', sole_app


def graphql_bypass(value, repository, repository_id, rule_id, app_id):
    report = {'result': 'validation-failed', 'sole_app_pr_only': False}
    if type(value) is not dict:
        return report
    if 'errors' in value:
        if type(value['errors']) is list and value['errors']:
            report['result'] = 'graphql-errors'
        return report  # Partial data cannot establish roster visibility.
    if type(value.get('data')) is not dict:
        return report
    state, repo = _identity(value['data'], 'repository', repository_id, repository)
    report['repository_identity'] = state
    if repo is None:
        return report
    state, rule = _identity(repo, 'ruleset', rule_id)
    report['ruleset_identity'] = state
    if rule is None:
        return report
    state, sole_app = _graphql_roster(rule, app_id)
    return {**report, 'result': 'observed', 'roster': state, 'sole_app_pr_only': sole_app}
