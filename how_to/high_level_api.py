import os

from iotics.lib.identity.api.high_level_api import get_rest_high_level_identity_api

RESOLVER_URL = os.environ.get('RESOLVER')
if not RESOLVER_URL:
    print('Missing RESOLVER url environment variable')
    exit(1)
print()
print('# High level Identity API example')
print('In this example each identity secrets (seeds and key names) are generated. The user is in charge to'
      'save those secrets to keep control of the identities')
print()
print('Features:')
print('\t 1. create USER and AGENT identities with authentication delegation')
print('\t 2. AGENT token generation for interaction with Iotics Host')
print('\t 3. create TWIN identity with control delegation')
print()
print()
api = get_rest_high_level_identity_api(resolver_url=RESOLVER_URL)

print('## 1. Create USER and AGENT identities with authentication delegation so the AGENT can authenticate '
      'on behalf of the USER')
user_seed, user_key_name, user_name = api.create_seed(), '#MyUserKey', '#MyUserName'
agent_seed, agent_key_name, agent_name = api.create_seed(), '#MyAgentKey', '#MyAgentName'

user_registered_id, agent_registered_id = api.create_user_and_agent_with_auth_delegation(user_seed=user_seed,
                                                                                         user_key_name=user_key_name,
                                                                                         user_name=user_name,
                                                                                         agent_seed=agent_seed,
                                                                                         agent_key_name=agent_key_name,
                                                                                         agent_name=agent_name,
                                                                                         delegation_name='#AuthDeleg')
print(f'User and agent identities have been created with authentication delegation')
print('For this example the following secrets have been generated:')
print()
print(f'Created USER identity: {user_registered_id.issuer}')
print(f'\t name: {user_name}')
print(f'\t key name: {user_key_name}')
print(f'\t seed: {user_seed.hex()}')
print()
print(f'Created AGENT identity: {agent_registered_id.issuer}')
print(f'\t name: {agent_name}')
print(f'\t key name: {agent_key_name}')
print(f'\t seed: {agent_seed.hex()}')
print()
print('> The api user is responsible to save the secrets to keep control of its own identity')

print()
print()
print('## 2. Create agent authentication token')
token = api.create_agent_auth_token(agent_registered_identity=agent_registered_id,
                                    user_did=user_registered_id.did,
                                    duration=3600)  # seconds
print('Token has been generated and can be used to interact with the Iotics host')
print(f'token: \'{token}\'')

print()
print()
print('## 3. Create a twin with control delegation to the AGENT so the AGENT can control the twin')
twin_seed, twin_key_name, twin_name = api.create_seed(), '#MyTwin1Key', '#MyTwin1Name'
twin_registered_id = api.create_twin_with_control_delegation(twin_seed=twin_seed,
                                                             twin_key_name=twin_key_name,
                                                             twin_name=twin_name,
                                                             agent_registered_identity=agent_registered_id,
                                                             delegation_name='#ControlDeleg')
print(f'Twin identity has been created with control delegation nto the AGENT')
print('For this example the following secrets have been generated:')
print(f'Created TWIN identity: {twin_registered_id.issuer}')
print()
print(f'\t name: {twin_name}')
print(f'\t key name: {twin_key_name}')
print(f'\t seed: {twin_seed.hex()}')

print()
print('> The api user is responsible to save the secrets to keep control of its own identity')
