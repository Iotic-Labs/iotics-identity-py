# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.


class IdentityBaseException(Exception):
    """
    Identity base exception. All the exceptions from the iotic.lib.identity extends this exception.
    """


class IdentityDependencyError(IdentityBaseException):
    """
    Raised when an unexpected error is raised by a dependency due to a version incompatibility.
    """


class IdentityValidationError(IdentityBaseException):
    """
    Raised when a user input is invalid.
    """


class IdentityInvalidDocumentError(IdentityValidationError):
    """
    Raised when a RegisterDocument is invalid.
    """


class IdentityInvalidProofError(IdentityInvalidDocumentError):
    """
    Raised when a Proof (for RegisterDocument, Delegation, ...) is invalid.
    """


class IdentityInvalidDocumentDelegationError(IdentityInvalidDocumentError):
    """
    Raised when a RegisterDocument delegation (authentication or control) is invalid.
    """


class IdentityRegisterDocumentKeyConflictError(IdentityInvalidDocumentError):
    """
    Raised when a RegisteredDocument key name is not unique.
    """


class IdentityRegisterDocumentKeyNotFoundError(IdentityInvalidDocumentError):
    """
    Raised when a register document key is not found.
    """


class IdentityRegisterIssuerNotFoundError(IdentityInvalidDocumentError):
    """
    Raised when a RegisteredDocument issuer is not found.
    """


class IdentityInvalidRegisterIssuerError(IdentityInvalidDocumentError):
    """
    Raised when a RegisteredDocument issuer is invalid.
    """


class IdentityResolverError(IdentityBaseException):
    """
    Raised when an error occurs while interacting with the resolver.
    """


class IdentityResolverConflictError(IdentityResolverError):
    """
    Raised when a register document already exist with a different owners
    """


class IdentityResolverDocNotFoundError(IdentityResolverError):
    """
    Raised when a RegisterDocument is not found against the resolver.
    """


class IdentityResolverCommunicationError(IdentityResolverError):
    """
    Raised when a communication error occurs while interacting with the resolver.
    """


class IdentityResolverTimeoutError(IdentityResolverError):
    """
    Raised when a timeout error occurs while interacting with the resolver.
    """


class IdentityResolverHttpError(IdentityResolverError):
    """
    Raised when a HTTPError occurs while interacting with the REST resolver.
    """


class IdentityResolverHttpDocNotFoundError(IdentityResolverHttpError, IdentityResolverDocNotFoundError):
    """
    Raised when a RegisterDocument is not found against the REST resolver.
    """


class IdentityAuthenticationFailed(IdentityBaseException):
    """
    Raised when verify authentication fails.
    """


class IdentityNotAllowed(IdentityAuthenticationFailed):
    """
    Raised when identity not allowed for authentication or control.
    """
