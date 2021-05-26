import os
from builtins import print
from pprint import pprint

from iotics.lib.identity.api.regular_api import get_rest_identity_api

RESOLVER_URL = os.environ.get('RESOLVER')
if not RESOLVER_URL:
    print('Missing RESOLVER url environment variable')
    exit(1)
print()
print('# Identity API example')
print('In this example each identity secrets (seeds and key names) are generated. The user is in charge to'
      'save those secrets to keep control of the identities')
print()
print('Features:')
print('\t 1. create USER identity')
print('\t 2. create AGENT identity')
print('\t 3. USER delegates authentication to AGENT')
print('\t 4. AGENT token generation for interaction with Iotics Host')
print('\t 5. create TWIN identity ')
print('\t 6. TWIN delegates control to AGENT')
print()
print()
api = get_rest_identity_api(resolver_url=RESOLVER_URL)
print('## 1. Create USER identity')
user_seed, user_key_name, user_name = api.create_seed(), '#MyUserKey', '#MyUserName'
user_registered_id = api.create_user_identity(user_seed=user_seed,
                                              user_key_name=user_key_name,
                                              user_name=user_name)
print(f'USER has been created')
print('For this example the following secrets have been generated:')
print()
print(f'Created USER identity: {user_registered_id.issuer}')
print(f'\t name: {user_name}')
print(f'\t key name: {user_key_name}')
print(f'\t seed: {user_seed.hex()}')
print()
print('> The api user is responsible to save the secrets to keep control of its own identity')
print('USER document:')
pprint(api.get_register_document(user_registered_id.did).to_dict())

print()
print()
print('## 2. Create AGENT identity')
agent_seed, agent_key_name, agent_name = api.create_seed(), '#MyAgentKey', '#MyAgentName'
agent_registered_id = api.create_agent_identity(agent_seed=agent_seed,
                                                agent_key_name=agent_key_name,
                                                agent_name=agent_name)
print(f'AGENT has been created')
print('For this example the following secrets have been generated:')
print()
print(f'Created AGENT identity: {agent_registered_id.issuer}')
print(f'\t name: {agent_name}')
print(f'\t key name: {agent_key_name}')
print(f'\t seed: {agent_seed.hex()}')
print()
print('> The api user is responsible to save the secrets to keep control of its own identity')
print('AGENT document:')
pprint(api.get_register_document(agent_registered_id.did).to_dict())

print()
print()
print('## 3. USER delegates authentication to the AGENT so the AGENT can authenticate on behalf of the USER')
api.user_delegates_authentication_to_agent(user_registered_identity=user_registered_id,
                                           agent_registered_identity=agent_registered_id,
                                           delegation_name='#AuthDeleg')

print(f'USER authentication delegation has been added to the USER document. Now the AGENT can create a token to '
      f'authenticate on behalf on the agent')
print('USER document:')
pprint(api.get_register_document(user_registered_id.did).to_dict())

print()
print()
print('## 4. Create agent authentication token')
token = api.create_agent_auth_token(agent_registered_identity=agent_registered_id,
                                    user_did=user_registered_id.did,
                                    duration=3600)  # seconds
print('Token has been generated and can be used to interact with the Iotics host')
print(f'token: \'{token}\'')

print()
print()
print('## 5. Create TWIN identity')
twin_seed, twin_key_name, twin_name = api.create_seed(), '#MyTwinKey', '#MyTwinName'
twin_registered_id = api.create_twin_identity(twin_seed=twin_seed,
                                              twin_key_name=twin_key_name,
                                              twin_name=twin_name)
print(f'TWIN has been created')
print('For this example the following secrets have been generated:')
print()
print(f'Created TWIN identity: {twin_registered_id.issuer}')
print(f'\t name: {twin_name}')
print(f'\t key name: {twin_key_name}')
print(f'\t seed: {twin_seed.hex()}')
print()
print('> The api user is responsible to save the secrets to keep control of its own identity')
print('TWIN document:')
pprint(api.get_register_document(twin_registered_id.did).to_dict())

print()
print()
print('## 6. TWIN delegates control to the AGENT so the AGENT can control the twin')
api.twin_delegates_control_to_agent(twin_registered_identity=twin_registered_id,
                                    agent_registered_identity=agent_registered_id,
                                    delegation_name='#ControlDeleg')

print(f'TWIN control delegation has been added to the TWIN document. Now the AGENT can control the twin '
      f'(Iotics create/update/...')
print('TWIN document:')
pprint(api.get_register_document(twin_registered_id.did).to_dict())
