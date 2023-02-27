""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
import requests
import os
import arrow
import urllib.parse
from django.conf import settings
from os.path import join
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import upload_file_to_cyops, download_file_from_cyops
from integrations.crudhub import make_request


logger = get_logger('opswat-metadefender-core')


class Opswat:
    def __init__(self, config):
        self.server_url = config.get('server_url').strip(" ").strip('/')
        if not (self.server_url.startswith('https://') or self.server_url.startswith('http://')):
            self.server_url = 'https://{0}'.format(self.server_url)
        self.verify_ssl = config.get('verify_ssl')
        self.username = config.get('username')
        self.password = config.get('password')
        self.token = self.login()

    def make_rest_call(self, endpoint, method='POST', params=None, data=None, headers=None, files=None):
        if headers is None:
            headers = {
                "apikey": self.token
            }
        url = '{0}{1}'.format(self.server_url, endpoint)
        logger.info('Request URL {0}'.format(url))
        try:
            response = requests.request(method, url, data=data, headers=headers,
                                        params=params, files=files, verify=self.verify_ssl)
            if response.ok:
                content_type = response.headers.get('Content-Type')
                if response.text != "" and 'application/json' in content_type:
                    return response.json()
                else:
                    return response.content
            else:
                if response.text != "":
                    err_resp = response.json()
                    if "error" in err_resp:
                        error_msg = "{0}: {1}".format(err_resp.get('error').get('code'),
                                                      err_resp.get('error').get('message'))
                        raise ConnectorError(error_msg)
                else:
                    error_msg = '{0}: {1}'.format(response.status_code, response.reason)
                    raise ConnectorError(error_msg)
        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except requests.exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except requests.exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))

    def login(self):
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "user": self.username,
            "password": self.password
        }
        response = self.make_rest_call('/login', data=json.dumps(payload), headers=headers)
        return response.get('session_id')

    def logout(self):
        self.make_rest_call('/logout')


def build_headers(params, opswat):
    payload = {
        "Content-Type": "application/octet-stream",
        "apikey": opswat.token,
        "filename": params.get('filename'),
        "rule": urllib.parse.quote(params.get('rule') if params.get('rule') is not None else ''),
        "callbackurl": params.get('callback_url'),
        "sanitizedurl": params.get('sanitized_url'),
        "downloadfrom": params.get('download_from')
    }
    payload.update(params.get('other_attributes'))
    headers = check_payload(payload)
    return headers


def check_payload(payload):
    updated_payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return updated_payload


def handle_params(params):
    value = str(params.get('value'))
    input_type = params.get('input_type')
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)
            attachment_data = make_request(value, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
            return file_iri
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                return value
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
    except Exception as err:
        logger.info('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                             (input_type, value.replace('/api/3/attachments/', '')))


def submitFile(file_iri):
    try:
        file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
        logger.info(file_path)
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()
        if file_data:
            files = {'file': file_data}
            return files
        raise ConnectorError('File size too large, submit file up to 32 MB')
    except Exception as Err:
        logger.error('Error in submitFile(): %s' % Err)
        raise ConnectorError('Error in submitFile(): %s' % Err)


def submit_file(config, params):
    opswat = Opswat(config)
    try:
        submit_type = params.get('submit_type')
        submit_mode = params.get('submit_mode')
        if submit_type == 'File Download URL':
            if submit_mode == 'Synchronous Mode':
                headers = build_headers(params, opswat)
                response = opswat.make_rest_call('/file/sync', headers=headers)
            else:
                headers = build_headers(params, opswat)
                response = opswat.make_rest_call('/file', headers=headers)
        else:
            if submit_mode == 'Synchronous Mode':
                headers = build_headers(params, opswat)
                file_iri = handle_params(params)
                files = submitFile(file_iri)
                response = opswat.make_rest_call('/file/sync', headers=headers, files=files)
            else:
                headers = build_headers(params, opswat)
                file_iri = handle_params(params)
                files = submitFile(file_iri)
                response = opswat.make_rest_call('/file', headers=headers, files=files)
        opswat.logout()
        return response
    except Exception as e:
        opswat.logout()
        logger.error('{0}'.format(e))
        raise ConnectorError('{0}'.format(e))


def get_hashcode_reputation(config, params):
    opswat = Opswat(config)
    try:
        hashcode = params.get("hashcode").strip(" ")
        if len(hashcode) == 32 or len(hashcode) == 40 or len(hashcode) == 64:
            endpoint = f'/hash/{hashcode}'
            response = opswat.make_rest_call(endpoint, method='GET')
            opswat.logout()
            return response
        else:
            raise ConnectionError("Invalid hash value.")
    except Exception as e:
        opswat.logout()
        logger.error('{0}'.format(e))
        raise ConnectorError('{0}'.format(e))


def download_sanitized_files(config, params):
    opswat = Opswat(config)
    try:
        data_id = params.get('data_id')
        endpoint = f'/file/converted/{data_id}'
        response = opswat.make_rest_call(endpoint, method='GET')
        opswat.logout()
        try:
            if response.get('message'):
                return response
        except:
            time = arrow.utcnow()
            file_name = f'opswat_metadefender_core_{time}'
            path = os.path.join(settings.TMP_FILE_ROOT, file_name)
            logger.error("Path: {0}".format(path))
            with open(path, 'wb') as fp:
                fp.write(response)
            attach_response = upload_file_to_cyops(file_path=file_name, filename=file_name,
                                                   name=file_name, create_attachment=True)
            return attach_response
    except Exception as e:
        opswat.logout()
        logger.error('{0}'.format(e))
        raise ConnectorError('{0}'.format(e))


def _check_health(config):
    try:
        opswat = Opswat(config)
        if opswat.token:
            logger.info('connector available')
            opswat.logout()
            return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'submit_file': submit_file,
    'get_hashcode_reputation': get_hashcode_reputation,
    'download_sanitized_files': download_sanitized_files
}
