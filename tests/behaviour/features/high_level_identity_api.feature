Feature: High Level Identity API

  Scenario: Create user and agent with authentication delegation
    Given a user seed, a user key name, an agent seed, and agent key name and a delegation name
    When I create user and agent with authentication delegation
    Then the user and agent documents are created and registered with authentication delegation

  Scenario: Create a Twin
    Given a twin seed and twin a key name
    When I create a twin
    Then the twin document is created and registered

  Scenario: Create a Twin with control delegation
    Given a twin seed, a twin key name and a registered agent identity
    When I create a twin with control delegation
    Then the twin document is created and registered with control delegation

  Scenario: Create an agent token
    Given a registered agent identity with auth delegation for a user_did and a duration
    When I create an agent auth token
    Then an authorized token is created

  Scenario: Get ownership of a twin
    Given a registered twin identity, a registered user identity and a new owner name
    When the user takes ownership of the registered twin
    Then the twin document is updated with the new owner
