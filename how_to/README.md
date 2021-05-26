Iotics Identity API How To
==========================

# High level Key concepts (not exhaustive)
An **Identity** is represented by a pair of secrets used to generate private and public keys.

A **pair of secrets** is composed of a secret seed (see how to generate below) and a key name (a string).
```
# Install iotics.lib.identity

# How to generate a seed using the code
[HighLevelIdentityApi or IdentityApi].create_seed()

# How to generate a see using the command line
iotics-identity-create-seed
```

A **Registered Identity** of type TWIN, AGENT or USER is created from an **Identity** (or **pair of secrets**).
When a **Registered Identity** is created a **Register document** associated to this identity is created and registered
 against the **Resolver**. The **Registered Identity** owns the document.

A **Registered Identity** can (not exhaustive):
- Add new owner (an **Identity** public key) to a **Register Document** the **Registered Identity** owns.
- Allow an other **Identity** (using its public key) to authenticate using the **Register Document** the **Registered Identity** owns.
- Delegate Authentication to an **other Registered Identity** on a **Register Document** the **Registered Identity** owns. The
**other Registered Identity** can authentication on behalf of the **Registered Identity**.
- Delegate Control to an **other Registered Identity** on a **Register Document** the **Registered Identity** owns. The
**other Registered Identity** can control the **Register Document** the **Registered Identity** owns.

# Minimal requirements to interact with Iotics Host

1. Authenticate with a token required by the Iotics Web API:
- Create a USER Registered Identity.
- Create an AGENT Registered Identity.
- Setup an Authentication delegation from the USER to the AGENT (USER delegates to the AGENT so AGENT can work on behalf of the USER).
- Create an authentication token.
- Use the token in the Iotics Web API headers.

2. Create Iotics Twins using the Iotics Web API:
- Create a TWIN Registered Identity.
- Setup a Control delegation from the TWIN to the AGENT (TWIN delegates to the AGENT so AGENT can control the TWIN).
- Use the twin decentralised identifier (registered_identity.did) to create the Iotics Twin using the Iotics Web API.

See the **High Level Identity API** and/or **Identity API** sections below to easily comply with those requirements and 
start using Iotics.

# High level Identity API

Minimal set of features to interact with Iotics Host. 

Key features:
- **Create USER and AGENT identities with authentication delegation**: set of identities required to authenticate against Iotics Host
- **Create an AGENT authentication token with duration**: token required by the Iotics Host API for authentication
- **Create TWIN identity with control delegation**: create a Twin identity to enable the creation and update of an Iotics Twin 

### Try it
> To run this example you will need a resolver url and to set the following environment variable:
>
> export RESOLVER=[resolver url]

See scripts: [How to use the high level identity API](./high_level_api.py)

Run it and have a look at the output
```bash
export RESOLVER='http://localhost:5000'
VERSION=dev pip install .
python ./high_level_api.py
```

See the ["code only" version of the "how to use the high level identity API"](./high_level_api_code_only.py) to
have a look at the code usage without noise (without print).


# Identity API

Set of features for basic identities management.

Key features:
- **Create a user identity**: needed to authenticate against the Iotics host
- **Create an agent identity**: needed to authenticate against the Iotics host
- **User identity delegates Authentication to the Agent identity**: Agent can authenticate on behalf of USer against the Iotics host.
- **Create an AGENT authentication token with duration**: token required by the Iotics Host API for authentication
- **Create a twin identity**: create a Twin identity to enable the creation of an Iotics Twin 
- **Twin delegates Control to Agent**: enable Agent to control (update/delete/...) an Iotics Twin


### Try it
> To run this example you will need a resolver url and to set the following environment variable:
>
> export RESOLVER=[resolver url]

See scripts: [How to use the identity API](./regular_api.py)

Run it and have a look at the output
```bash
export RESOLVER='http://localhost:5000'
VERSION=dev pip install .
python ./regular_api.py
```

See the ["code only" version of the "how to use the identity API"](./regular_api_code_only.py) to
have a look at the code usage without noise (without print).
