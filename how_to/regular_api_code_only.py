import os

from iotics.lib.identity.api.regular_api import get_rest_identity_api

RESOLVER_URL = os.environ.get('RESOLVER')
api = get_rest_identity_api(resolver_url=RESOLVER_URL)

# -- Create User ---------------------------------------------------------------------------------------------------- #
user_seed, user_key_name, user_name = api.create_seed(), '#MyUserKey', '#MyUserName'
user_registered_id = api.create_user_identity(user_seed=user_seed,
                                              user_key_name=user_key_name,
                                              user_name=user_name)

# -- Create Agent --------------------------------------------------------------------------------------------------- #
agent_seed, agent_key_name, agent_name = api.create_seed(), '#MyAgentKey', '#MyAgentName'
agent_registered_id = api.create_agent_identity(agent_seed=agent_seed,
                                                agent_key_name=agent_key_name,
                                                agent_name=agent_name)

# -- Delegate Authentication ---------------------------------------------------------------------------------------- #
api.user_delegates_authentication_to_agent(user_registered_identity=user_registered_id,
                                           agent_registered_identity=agent_registered_id,
                                           delegation_name='#AuthDeleg')

# -- Create token --------------------------------------------------------------------------------------------------- #
token = api.create_agent_auth_token(agent_registered_identity=agent_registered_id,
                                    user_did=user_registered_id.did,
                                    duration=3600)  # seconds

# -- Create Twin ---------------------------------------------------------------------------------------------------- #
twin_seed, twin_key_name, twin_name = api.create_seed(), '#MyTwinKey', '#MyTwinName'
twin_registered_id = api.create_twin_identity(twin_seed=twin_seed,
                                              twin_key_name=twin_key_name,
                                              twin_name=twin_name)

# -- Delegate Control ----------------------------------------------------------------------------------------------- #
api.twin_delegates_control_to_agent(twin_registered_identity=twin_registered_id,
                                    agent_registered_identity=agent_registered_id,
                                    delegation_name='#ControlDeleg')

