# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.const import DOCUMENT_MAX_COMMENT_LENGTH, DOCUMENT_MAX_LABEL_LENGTH, DOCUMENT_MAX_URL_LENGTH
from iotics.lib.identity.error import IdentityValidationError
from iotics.lib.identity.register.document import Metadata


def test_can_serialise_full_document_to_dict(full_doc, doc_keys):
    dict_doc = full_doc.to_dict()
    assert dict_doc.pop('updateTime') == full_doc.update_time

    assert dict_doc == {'@context': 'https://w3id.org/did/v1',
                        'id': full_doc.did,
                        'ioticsDIDType': full_doc.purpose.value,
                        'ioticsSpecVersion': full_doc.spec_version,
                        'controller': str(full_doc.controller),
                        'creator': full_doc.creator,
                        'metadata': full_doc.metadata.to_dict(),
                        'revoked': full_doc.revoked,
                        'proof': full_doc.proof,
                        'publicKey': [doc_keys['#pub_key1'].to_dict(), doc_keys['#pub_key2'].to_dict()],
                        'authentication': [doc_keys['#auth_key1'].to_dict(), doc_keys['#auth_key2'].to_dict()],
                        'delegateControl': [doc_keys['#deleg_control_key1'].to_dict(),
                                            doc_keys['#deleg_control_key2'].to_dict()],
                        'delegateAuthentication': [doc_keys['#deleg_auth_key1'].to_dict(),
                                                   doc_keys['#deleg_auth_key2'].to_dict()],
                        }


def test_can_serialise_a_minimal_doc_to_dict(minimal_doc, min_doc_owner_pub_key):
    dict_doc = minimal_doc.to_dict()
    assert dict_doc.pop('updateTime') == minimal_doc.update_time

    assert dict_doc == {'@context': 'https://w3id.org/did/v1',
                        'id': minimal_doc.did,
                        'ioticsDIDType': minimal_doc.purpose.value,
                        'ioticsSpecVersion': minimal_doc.spec_version,
                        'metadata': Metadata().to_dict(),
                        'revoked': minimal_doc.revoked,
                        'proof': minimal_doc.proof,
                        'publicKey': [min_doc_owner_pub_key.to_dict()],
                        'authentication': [],
                        'delegateControl': [],
                        'delegateAuthentication': [],
                        }


def test_can_build_doc_metadata():
    label = 'a label'
    comment = 'a comment'
    url = 'http://an/url'
    metadata = Metadata.build(label, comment, url)
    assert metadata.label == label
    assert metadata.comment == comment
    assert metadata.url == url
    assert metadata.to_dict() == {'label': label,
                                  'comment': comment,
                                  'url': url}


def test_can_build_doc_metadata_from_dict():
    data = {'label': 'a label',
            'comment': 'a comment',
            'url': 'http://an/url'}
    metadata = Metadata.from_dict(data)
    assert metadata.label == data['label']
    assert metadata.comment == data['comment']
    assert metadata.url == data['url']


@pytest.mark.parametrize('invalid_input', (dict(label='a' * (DOCUMENT_MAX_LABEL_LENGTH + 1)),
                                           dict(comment='a' * (DOCUMENT_MAX_COMMENT_LENGTH + 1)),
                                           dict(url='a' * (DOCUMENT_MAX_URL_LENGTH + 1))))
def test_build_doc_metadata_raises_validaion_error_in_invalid_data(invalid_input):
    params = dict(label='a label', comment='a comment', url='http://an/url')
    params.update(invalid_input)
    with pytest.raises(IdentityValidationError):
        Metadata.build(**params)
