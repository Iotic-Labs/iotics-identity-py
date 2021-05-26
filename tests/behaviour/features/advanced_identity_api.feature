Feature: Advanced Identity API

  Scenario: Get a register document from a registered identity
    Given a registered identity
    When I get the associated document
    Then the registered identity issuer did is equal to the document did

  Scenario: Register identity owning the document is in the document public key
    Given a registered identity owning the document
    When I get the associated document
    Then the register document has the registered identity public key

  Scenario: Register identity owning the document is allowed for control and authentication
    Given a registered identity owning the document
    When I check if the registered identity is allowed for control and authentication on the associated document
    Then the registered identity is allowed

  Scenario: Several registered identity can belong to the same document
    Given a register document with several owners
    When I get the associated document
    Then the register document has several public keys

  Scenario: Add a register document owner
    Given an register document I owned and a new owner name and public key
    When I add the new owner to the document
    Then the new owner is allowed for authentication and control on the document

  Scenario: Remove a register document owner
    Given an register document I owned and an other existing owner name and public key
    When I remove the other owner from the document
    Then the removed owner is not allowed for authentication or control on the document

  Scenario: Revoke a register document owner
    Given an register document I owned and an other existing owner name and public key
    When I revoke the other owner key
    Then the revoked owner is not allowed for authentication or control on the document

  Scenario: Add an authentication key to a register document
    Given a register document I owned and a new authentication name and public key
    When I add the new authentication key to the document
    Then the authentication key owner is allowed for authentication on the document

  Scenario: Remove an authentication key from a register document
    Given a register document I owned and an existing authentication name and public key
    When I remove the authentication key from the document
    Then the removed authentication key owner is not allowed for authentication on the document

  Scenario: Revoke an authentication key
    Given a register document I owned and an existing authentication name and public key
    When I revoke the authentication key
    Then the revoked authentication key owner is not allowed for authentication on the document

  # Wording
  # DelegatingRId => delegating registered identity => the identity delegating auth or control
  # DelegatedRId => delegated registered identity => the identity working on behalf of the delegating identity
  Scenario: Add a control delegation between 2 existing registered identities
    Given a DelegatingRId owning a document and a DelegatedRId
    When the DelegatingRId delegates control to the DelegatedRId
    Then the DelegatedRId is allowed for control on the document owned by the DelegatingRId

  Scenario: Add a control delegation proof (created by an other registered identity) to a document
    Given a DelegatingRId owning a document and a delegation proof created by a DelegatedRId
    When I add the control delegation proof to the document owned by the DelegatingRId
    Then the DelegatedRId is allowed for control on the document owned by the DelegatingRId

  Scenario: Remove a control delegation proof from a register document
    Given a DelegatingRId owning a document with a control delegation proof created by a DelegatedRId
    When I remove the control delegation proof from the document owned by the DelegatingRId
    Then the DelegatedRId is not allowed for control on the document owned by the DelegatingRId after delegation remove

  Scenario: Revoke a control delegation proof
    Given a DelegatingRId owning a document with a control delegation proof created by a DelegatedRId
    When I revoke the control delegation proof
    Then the DelegatedRId is not allowed for control on the document owned by the DelegatingRId after delegation revoke

  Scenario: Add an authentication delegation between 2 existing registered identities
    Given a DelegatingRId owning a document and a DelegatedRId
    When the DelegatingRId delegates authentication to the DelegatedRId
    Then the DelegatedRId is allowed for authentication on the document owned by the DelegatingRId

  Scenario: Add an authentication delegation proof (created by an other registered identity) to a document
    Given a DelegatingRId owning a document and a delegation proof created by a DelegatedRId
    When I add the authentication delegation proof to the document owned by the DelegatingRId
    Then the DelegatedRId is allowed for authentication on the document owned by the DelegatingRId

  Scenario: Remove an authentication delegation proof from a register document
    Given a DelegatingRId owning a document with an auth delegation proof created by a DelegatedRId
    When I remove the authentication delegation proof from the document owned by the DelegatingRId
    Then the DelegatedRId is not allowed for authentication on the document owned by the DelegatingRId after delegation remove

  Scenario: Revoke an authentication delegation proof
    Given a DelegatingRId owning a document with an auth delegation proof created by a DelegatedRId
    When I revoke the authentication delegation proof
    Then the DelegatedRId is not allowed for authentication on the document owned by the DelegatingRId after delegation revoke

  Scenario: Authentication delegation is still valid if the delegated identity has several owners and the key used in the proof is revoked
    Given a DelegatingRId owning a document with an auth delegation proof created by a DelegatedRId with several owner
    When the DelegatedRId owner used for the proof is revoked
    Then the DelegatedRId is still allowed for authentication on the document owned by the DelegatingRId

  Scenario: Authentication delegation is not valid if the delegated identity has several owners and the key used in the proof is removed
    Given a DelegatingRId owning a document with an auth delegation proof created by a DelegatedRId with several owner
    When the DelegatedRId owner used for the proof is removed
    Then the DelegatedRId is not allowed for authentication on the document owned by the DelegatingRId anymore

  Scenario: Control delegation is still valid if the delegated identity has several owners and the key used in the proof is revoked
    Given a DelegatingRId owning a document with a control delegation proof created by a DelegatedRId with several owner
    When the DelegatedRId owner used for the proof is revoked
    Then the DelegatedRId is still allowed for control on the document owned by the DelegatingRId

  Scenario: Control delegation is not valid if the delegated identity has several owners and the key used in the proof is removed
    Given a DelegatingRId owning a document with a control delegation proof created by a DelegatedRId with several owner
    When the DelegatedRId owner used for the proof is removed
    Then the DelegatedRId is not allowed for control on the document owned by the DelegatingRId anymore

  Scenario: Document controller is allowed for auth and control
    Given a registered identity owning a document and a controller (registered identity)
    When I set the controller on my document
    Then the controller is allowed for control and authentication
