#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: venafi_certificate_revoke
short_description: Revoke a certificate on CyberArk platforms
description:
    - CyberArk certificate revocation module for working with CyberArk Certificate Manager, Self-Hosted
      (TPP), CyberArk Certificate Manager, SaaS, and Strata Cloud Manager (NGTS).
    - It revokes a certificate by delegating to the C(vcert-python) SDK (C(revoke_cert)), mirroring the
      Go C(vcert revoke) command.
    - Self-Hosted (TPP) revokes a certificate identified by its C(certificate_dn) or its SHA-1
      C(thumbprint), and honors retire/I(no_retire).
    - SaaS and NGTS (Strata Cloud Manager) revoke a certificate identified by its SHA-1 C(thumbprint)
      only; C(certificate_dn) and the C(ca-compromise) reason are not supported, and I(no_retire) is
      ignored. SaaS and NGTS revocation requires C(vcert) >= 0.21.0.
    - Revocation is an imperative operation - the module always attempts to revoke the certificate. The
      inherited I(state) option is accepted for consistency with the other modules but is ignored (the
      module never enrolls or deletes files).
    - NGTS (Strata Cloud Manager) is selected by supplying the OAuth2 service-account credentials
      (I(client_id), I(client_secret), and I(tsg_id) or I(scope)); SaaS by supplying I(token); otherwise
      Self-Hosted (TPP) is used.
version_added: "1.3.0"
author: CyberArk (@cyberark)
options:
    thumbprint:
        description:
            - The SHA-1 thumbprint (fingerprint) of the certificate to revoke.
            - B(Required) for CyberArk Certificate Manager, SaaS and NGTS (Strata Cloud Manager).
            - For Self-Hosted (TPP) supply either I(thumbprint) or I(certificate_dn), but not both.
        required: false
        type: str
    certificate_dn:
        aliases:
            - cert_id
        description:
            - The Distinguished Name (DN) of the certificate to revoke on CyberArk Certificate Manager,
              Self-Hosted (TPP). Equivalent to the C(--id) flag of the Go C(vcert revoke) command.
            - B(Only) supported by Self-Hosted (TPP). Rejected for SaaS and NGTS.
            - Supply either I(certificate_dn) or I(thumbprint), but not both.
        required: false
        type: str
    reason:
        description:
            - The reason for revoking the certificate.
            - C(ca-compromise) is B(only) supported by Self-Hosted (TPP); SaaS and NGTS reject it.
        default: none
        choices:
            - none
            - key-compromise
            - ca-compromise
            - affiliation-changed
            - superseded
            - cessation-of-operation
        type: str
    comments:
        description:
            - A free-text comment stored with the revocation request.
        default: revocation request from Ansible
        type: str
    ca_account_name:
        description:
            - The name of the CA account to target for revocation on CyberArk Certificate Manager, SaaS
              or NGTS (Strata Cloud Manager). Resolved to a CA-account id by the SDK.
            - Leave unset (the common case) for certificates issued by CM SaaS itself.
            - Ignored by Self-Hosted (TPP).
        required: false
        type: str
    no_retire:
        description:
            - When revoking by I(certificate_dn) on Self-Hosted (TPP), keep the certificate object
              instead of retiring (disabling) it. Equivalent to the C(--no-retire) flag of the Go
              C(vcert revoke) command.
            - Ignored when revoking by I(thumbprint), and ignored by SaaS and NGTS.
        default: false
        type: bool
seealso:
    - module: venafi.machine_identity.venafi_certificate
extends_documentation_fragment:
    - venafi.machine_identity.common_options
    - venafi.machine_identity.venafi_connection_options
'''

EXAMPLES = r'''
# Revoke a certificate on NGTS (Strata Cloud Manager) by thumbprint
- name: "revoke_ngts_certificate"
  venafi.machine_identity.venafi_certificate_revoke:
    client_id: "my-service-account-client-id"
    client_secret: "my-service-account-client-secret"
    tsg_id: "1000000001"
    thumbprint: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
    reason: "cessation-of-operation"
  register: revokeout
- name: "dump revoke output"
  debug:
    msg: "{{ revokeout }}"

# Revoke a certificate on CyberArk Certificate Manager, SaaS by thumbprint
- name: "revoke_saas_certificate"
  venafi.machine_identity.venafi_certificate_revoke:
    token: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    thumbprint: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
    reason: "key-compromise"

# Revoke a certificate on CyberArk Certificate Manager, Self-Hosted (TPP) by DN and retire it
- name: "revoke_tpp_certificate_by_dn"
  venafi.machine_identity.venafi_certificate_revoke:
    url: "https://tpp.example.com"
    access_token: "AnkEFGHY+IpaTPyiM3DHsMR=="
    certificate_dn: "\\VED\\Policy\\example\\my-certificate"
    reason: "superseded"

# Revoke a certificate on Self-Hosted (TPP) by DN but keep the certificate object
- name: "revoke_tpp_certificate_no_retire"
  venafi.machine_identity.venafi_certificate_revoke:
    url: "https://tpp.example.com"
    access_token: "AnkEFGHY+IpaTPyiM3DHsMR=="
    certificate_dn: "\\VED\\Policy\\example\\my-certificate"
    reason: "superseded"
    no_retire: true

# Revoke a certificate on Self-Hosted (TPP) by thumbprint
- name: "revoke_tpp_certificate_by_thumbprint"
  venafi.machine_identity.venafi_certificate_revoke:
    url: "https://tpp.example.com"
    access_token: "AnkEFGHY+IpaTPyiM3DHsMR=="
    thumbprint: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
'''

RETURN = '''
certificate_id:
    description: The identifier of the revoked certificate.
    returned: when the backend is CyberArk Certificate Manager, SaaS or NGTS
    type: str
    sample: "abcd1234-5678-90ef-ghij-klmnopqrstuv"

thumbprint:
    description: The SHA-1 thumbprint of the revoked certificate.
    returned: when the backend is CyberArk Certificate Manager, SaaS or NGTS
    type: str
    sample: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"

serial:
    description: The serial number of the revoked certificate.
    returned: when the backend is CyberArk Certificate Manager, SaaS or NGTS
    type: str
    sample: "0F:1E:2D:3C"

status:
    description: The status of the revocation request as returned by the backend.
    returned: when the backend is CyberArk Certificate Manager, SaaS or NGTS
    type: str
    sample: "SUBMITTED"

rejection_reason:
    description: The reason a pending revocation request was rejected, when available.
    returned: when the revocation request is pending or rejected on CyberArk Certificate Manager, SaaS or NGTS
    type: str
    sample: "Not authorized"

revocation_details:
    description: The raw revocation response body returned by the backend.
    returned: when the backend is CyberArk Certificate Manager, Self-Hosted (TPP)
    type: dict
    sample: {}
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native
try:
    from ansible_collections.venafi.machine_identity.plugins.module_utils.common_utils \
        import (get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec,
                is_ngts_request, get_revocation_reason, REVOCATION_REASONS,
                REVOKE_REASON_NONE, REVOKE_REASON_CA_COMPROMISE, VenafiAnsibleError, F_APIKEY)
except ImportError:
    from plugins.module_utils.common_utils \
        import (get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec,
                is_ngts_request, get_revocation_reason, REVOCATION_REASONS,
                REVOKE_REASON_NONE, REVOKE_REASON_CA_COMPROMISE, VenafiAnsibleError, F_APIKEY)

HAS_VCERT = True
try:
    from vcert import RevocationRequest
except ImportError:
    HAS_VCERT = False

F_THUMBPRINT = 'thumbprint'
F_CERTIFICATE_DN = 'certificate_dn'
F_REASON = 'reason'
F_COMMENTS = 'comments'
F_CA_ACCOUNT_NAME = 'ca_account_name'
F_NO_RETIRE = 'no_retire'

F_CHANGED = 'changed'
F_CHANGED_MSG = 'changed_msg'

BACKEND_TPP = 'tpp'
BACKEND_CLOUD = 'cloud'
BACKEND_NGTS = 'ngts'

# Human-readable backend labels for error/warning messages.
_BACKEND_LABELS = {
    BACKEND_CLOUD: 'CyberArk Certificate Manager, SaaS',
    BACKEND_NGTS: 'NGTS (Strata Cloud Manager)',
}


class VCertificateRevoke:
    def __init__(self, module):
        """
        :param AnsibleModule module:
        """
        self.module = module  # type: AnsibleModule
        self.connection = get_venafi_connection(module)
        self.thumbprint = module.params[F_THUMBPRINT]  # type: str
        self.certificate_dn = module.params[F_CERTIFICATE_DN]  # type: str
        self.reason = module.params[F_REASON]  # type: str
        self.comments = module.params[F_COMMENTS]  # type: str
        self.ca_account_name = module.params[F_CA_ACCOUNT_NAME]  # type: str
        self.no_retire = module.params[F_NO_RETIRE]  # type: bool

        self.changed = False
        self.result = None
        self.request = self._build_request()

    def _backend(self):
        """
        Infer the target backend from the supplied credentials, only for input validation and
        messaging. The actual connection is selected by get_venafi_connection(), so an incorrect
        inference still fails cleanly at the SDK layer.

        :rtype: str
        """
        if is_ngts_request(self.module):
            return BACKEND_NGTS
        if self.module.params.get(F_APIKEY):
            return BACKEND_CLOUD
        return BACKEND_TPP

    def _build_request(self):
        """
        Validate the identifier/reason combination for the target backend and build the
        vcert.RevocationRequest, mirroring the Go vcert revoke command.

        :rtype: RevocationRequest
        """
        backend = self._backend()

        if backend in (BACKEND_CLOUD, BACKEND_NGTS):
            label = _BACKEND_LABELS[backend]
            if not self.thumbprint:
                self.module.fail_json(
                    msg="%s revocation requires 'thumbprint' (the SHA-1 fingerprint); "
                        "'certificate_dn' is only supported by CyberArk Certificate Manager, "
                        "Self-Hosted (TPP)." % label)
            if self.reason == REVOKE_REASON_CA_COMPROMISE:
                self.module.fail_json(
                    msg="reason 'ca-compromise' is only supported by CyberArk Certificate Manager, "
                        "Self-Hosted (TPP); %s does not accept it." % label)
            if self.no_retire:
                self.module.warn("'no_retire' is ignored for %s revocation." % label)

        # disable/no_retire mapping matches Go doCommandRevoke1: retire (disable) on the DN path
        # unless no_retire is set; the thumbprint path never retires (and Cloud/NGTS ignore it).
        if self.certificate_dn:
            disable = not self.no_retire
        else:
            disable = False

        try:
            reason_code = get_revocation_reason(self.reason)
        except VenafiAnsibleError as e:
            self.module.fail_json(msg=to_native(e))
            return None  # unreachable; fail_json raises. Keeps static analysis happy.

        request = RevocationRequest(
            req_id=self.certificate_dn,
            thumbprint=self.thumbprint,
            reason=reason_code,
            comments=self.comments,
            disable=disable,
        )
        # ca_account_name only exists on newer SDKs; set it via attribute so the module still
        # works against an SDK whose RevocationRequest predates the field.
        if self.ca_account_name:
            request.ca_account_name = self.ca_account_name

        return request

    def check(self):
        """
        Revocation is imperative and has no cheap "already revoked?" lookup, so check() is
        side-effect-free and optimistic: it reports a change whenever a valid identifier was
        supplied (a revoke would be attempted). Mirrors the Go reference, which performs no
        pre-check before revoking.

        :rtype: dict[str, Any]
        """
        identifier = self.thumbprint or self.certificate_dn
        return {
            F_CHANGED: True,
            F_CHANGED_MSG: "Revocation will be requested for %s" % identifier,
        }

    def revoke(self):
        """
        Perform the revocation exactly once.

        :rtype: None
        """
        try:
            self.result = self.connection.revoke_cert(self.request)
            self.changed = True
        except NotImplementedError:
            self.module.fail_json(
                msg="Certificate revocation is not supported for this backend or vcert version. "
                    "SaaS and NGTS (Strata Cloud Manager) revocation requires vcert >= 0.21.0, and "
                    "test_mode (the fake connector) does not support revocation.")
        except Exception as e:
            self.module.fail_json(msg="Failed to revoke certificate. Error: %s" % to_native(e))

    def dump(self):
        """
        Build the module result. SaaS/NGTS return a structured dict; Self-Hosted (TPP) returns the
        raw response body (surfaced as revocation_details).

        :rtype: dict[str, Any]
        """
        result = {F_CHANGED: self.changed}
        data = self.result
        if isinstance(data, dict) and any(k in data for k in ('id', 'thumbprint', 'serial', 'status')):
            # CyberArk Certificate Manager, SaaS / NGTS structured response.
            if data.get('id') is not None:
                result['certificate_id'] = data.get('id')
            if data.get('thumbprint') is not None:
                result['thumbprint'] = data.get('thumbprint')
            if data.get('serial') is not None:
                result['serial'] = data.get('serial')
            if data.get('status') is not None:
                result['status'] = data.get('status')
            if data.get('rejection_reason') is not None:
                result['rejection_reason'] = data.get('rejection_reason')
        elif data:
            # Self-Hosted (TPP) raw response body.
            result['revocation_details'] = data

        return result


def main():
    args = module_common_argument_spec()
    args.update(venafi_common_argument_spec())
    args.update(
        thumbprint=dict(type='str', required=False, default=None),
        certificate_dn=dict(type='str', aliases=['cert_id'], required=False, default=None),
        reason=dict(type='str', choices=REVOCATION_REASONS, default=REVOKE_REASON_NONE),
        comments=dict(type='str', default='revocation request from Ansible'),
        ca_account_name=dict(type='str', required=False, default=None),
        no_retire=dict(type='bool', default=False),
    )
    module = AnsibleModule(
        argument_spec=args,
        supports_check_mode=True,
        required_one_of=[[F_THUMBPRINT, F_CERTIFICATE_DN]],
        mutually_exclusive=[[F_THUMBPRINT, F_CERTIFICATE_DN]],
    )

    if not HAS_VCERT:
        module.fail_json(msg='"vcert" python library is required')

    vcert = VCertificateRevoke(module)

    check_result = vcert.check()
    if module.check_mode:
        module.exit_json(**check_result)

    vcert.revoke()
    module.exit_json(**vcert.dump())


if __name__ == '__main__':
    main()
