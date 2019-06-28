#!/usr/bin/env python

import argparse
import json
import oci
import os
import requests
import sys


def __dump_json(to_print):
    return json.dumps(to_print, sort_keys=True, indent=4, separators=(',', ': '))

def __get_oci_config(config_file, profile):
    if not os.path.exists(config_file):
        sys.stdout.write("{0} not found, OCI CLI is not configured\n".format(os.path.abspath(config_file)))
        sys.stdout.write("\tSee https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/cliconfigure.htm\n")
        sys.stdout.flush()
        sys.exit(1)

    config = oci.config.from_file(config_file, profile)

    return config

def __prompt_for_passphrase():
    return getpass.getpass('Private key passphrase:')

def __get_oci_auth_signer(auth, oci_config):
    instance_principal_auth = auth == 'instance_principal'
    session_token_auth = auth == 'security_token'
    delegation_token_auth = auth == 'instance_obo_user'
    signer = None

    if delegation_token_auth:
        delegation_token = None
        delegation_token_location = oci_config.get('delegation_token_file')
        if delegation_token_location is None:
            raise ValueError('ERROR: Please specify the location of the delegation_token_file in the config.')
        expanded_delegation_token_location = os.path.expanduser(delegation_token_location)
        if not os.path.exists(expanded_delegation_token_location):
            raise IOError("ERROR: delegation_token_file not found at " + expanded_delegation_token_location)
        with open(expanded_delegation_token_location, 'r') as delegation_token_file:
            delegation_token = delegation_token_file.read().strip()
        if delegation_token is None:
            raise ValueError('ERROR: delegation_token was not provided.')
        signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)
    elif instance_principal_auth:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    elif session_token_auth:
        security_token_location = oci_config.get('security_token_file')
        if not security_token_location:
            sys.exit("ERROR: Config value for 'security_token_file' must be specified when using --auth security_token")

        expanded_security_token_location = os.path.expanduser(security_token_location)
        if not os.path.exists(expanded_security_token_location):
            sys.exit("ERROR: File specified by 'security_token_file' does not exist: {}".format(expanded_security_token_location))

        with open(expanded_security_token_location, 'r') as security_token_file:
            token = security_token_file.read()

        try:
            private_key = oci.signer.load_private_key_from_file(oci_config.get('key_file'), oci_config.get('pass_phrase'))
        except exceptions.MissingPrivateKeyPassphrase:
            oci_config['pass_phrase'] = __prompt_for_passphrase()
            private_key = oci.signer.load_private_key_from_file(oci_config.get('key_file'), oci_config.get('pass_phrase'))
        signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
    else:
        signer = oci.Signer(tenancy=oci_config.get('tenancy'), user=oci_config.get('user'), fingerprint=oci_config.get('fingerprint'),
            private_key_file_location=oci_config.get('key_file'), pass_phrase=oci_config.get('pass_phrase'))


    return signer

class EnvDefault(argparse.Action):
    def __init__(self, envvar, required=True, default=None, **kwargs):
        if envvar in os.environ:
            default = os.environ[envvar]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required,
                                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)


def main(argv):
    parser = argparse.ArgumentParser(description='OCI curl')

    debug_group = parser.add_mutually_exclusive_group()
    debug_group.add_argument('-i', '--info', dest='info', default=False, action='store_true',
            help='Produce informational output')
    debug_group.add_argument('-d', '--debug', dest='debug', default=False, action='store_true',
            help='Produce debug output')

    parser.add_argument('--config-file', dest="config_file", default=os.path.expanduser("~/.oci/config"),
            metavar='TEXT', help='The path to the config file.  [default: ~/.oci/config]')
    parser.add_argument('--profile', dest="profile", action=EnvDefault, envvar='OCI_CLI_PROFILE', default='DEFAULT',
            metavar='TEXT', help='The profile in the config file to load. This profile will also be used to locate any default parameter values which have been specified in the OCI CLI-specific configuration file.  [default: DEFAULT]')
    parser.add_argument('--auth', dest="auth", choices=['api_key','instance_principal','security_token','instance_obo_user'], default='api_key', action=EnvDefault, envvar='OCI_CLI_AUTH',
            metavar='TEXT', help='The type of auth to use for the API request.  By default the API key in your config file will be used.  This value can also be provided in the OCI_CLI_AUTH environmen')
    parser.add_argument('-X,--request', dest="request_method", default='GET', 
            metavar='<command>', help='(HTTP)  Specifies a custom request method to use when communicating with the HTTP server [default: GET]')
    parser.add_argument('-H,--header', dest="headers", action='append',
            metavar='<header>', help='Extra header to include in the request when sending HTTP to a server.')
    parser.add_argument('--data', dest="data",
            metavar='<data>', help='Extra header to include in the request when sending HTTP to a server.')
    parser.add_argument('url', metavar='<url>', help='Destination HTTP URL')

    args = parser.parse_args()

    config = __get_oci_config(args.config_file, args.profile)
    signer = __get_oci_auth_signer(args.auth, config)
    
    headers = {}
    for header_text in args.headers if args.headers != None else []:
        (name,val) = header_text.split(':',1)
        headers[name.strip()] = val.strip()

    data = None
    if args.data:
        data = args.data
        if args.data.startswith("@"):
            with open(args.data[1:], 'r') as file:
                data = file.read()
    
    response = requests.request(args.request_method.upper(), args.url, auth=signer, headers=headers, data=data)
    response.raise_for_status()
    print(response.text)

if __name__ == '__main__':
    main(sys.argv)
