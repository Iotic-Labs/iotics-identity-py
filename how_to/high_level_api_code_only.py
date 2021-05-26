import os

from iotics.lib.identity.api.high_level_api import get_rest_high_level_identity_api

RESOLVER_URL = os.environ.get('RESOLVER')

api = get_rest_high_level_identity_api(resolver_url=RESOLVER_URL)

# -- Create User and Agent with Authentication delegation --------------------------------------------------------- #
user_seed, user_key_name, user_name = api.create_seed(), '#MyUserKey', '#MyUserName'
agent_seed, agent_key_name, agent_name = api.create_seed(), '#MyAgentKey', '#MyAgentName'

user_registered_id, agent_registered_id = api.create_user_and_agent_with_auth_delegation(user_seed=user_seed,
                                                                                         user_key_name=user_key_name,
                                                                                         user_name=user_name,
                                                                                         agent_seed=agent_seed,
                                                                                         agent_key_name=agent_key_name,
                                                                                         agent_name=agent_name,
                                                                                         delegation_name='#AuthDeleg')
# -- Create token -------------------------------------------------------------------------------------------------- #

token = api.create_agent_auth_token(agent_registered_identity=agent_registered_id,
                                    user_did=user_registered_id.did,
                                    duration=3600)  # seconds

# -- Create Twin with Control delegation --------------------------------------------------------------------------- #
twin_seed, twin_key_name, twin_name = api.create_seed(), '#MyTwin1Key', '#MyTwin1Name'
twin_registered_id = api.create_twin_with_control_delegation(twin_seed=twin_seed,
                                                             twin_key_name=twin_key_name,
                                                             twin_name=twin_name,
                                                             agent_registered_identity=agent_registered_id,
                                                             delegation_name='#ControlDeleg')
