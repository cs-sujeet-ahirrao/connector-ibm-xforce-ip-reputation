""" 
Copyright start 
Copyright (C) 2008 - 2021 Fortinet Inc. 
All rights reserved. 
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE 
Copyright end 
"""
import base64
import requests

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('ibm-xforce-ip-reputation')


class IBMXForceIPReputation(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('api_key')
        self.api_password = config.get('api_password')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint=None, method='GET', data=None, params=None, files=None):
        try:
            url = self.server_url + endpoint
            b64_credential = base64.b64encode((self.api_key + ":" + self.api_password).encode('utf-8')).decode()
            headers = {'Authorization': "Basic " + b64_credential, 'Content-Type': 'application/json'}
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_ips_by_category(config, params):
    ip_rep = IBMXForceIPReputation(config)
    param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    endpoint = 'ipr/'
    return ip_rep.make_request(endpoint=endpoint, params=param_dict)


def get_ip_report(config, params):
    ip_rep = IBMXForceIPReputation(config)
    endpoint = 'ipr/' + str(params.get('ip'))
    return ip_rep.make_request(endpoint=endpoint)


def get_ip_reputation(config, params):
    ip_rep = IBMXForceIPReputation(config)
    endpoint = 'ipr/history/' + str(params.get('ip'))
    return ip_rep.make_request(endpoint=endpoint)


def get_malware_reputation(config, params):
    ip_rep = IBMXForceIPReputation(config)
    endpoint = 'ipr/malware/' + str(params.get('ip'))
    return ip_rep.make_request(endpoint=endpoint)


def get_networks_for_asn(config, params):
    ip_rep = IBMXForceIPReputation(config)
    endpoint = 'ipr/asn/' + str(params.get('asn'))
    return ip_rep.make_request(endpoint=endpoint)


def _check_health(config):
    try:
        params = {'ip': '8.8.8.8'}
        res = get_ip_reputation(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_ips_by_category': get_ips_by_category,
    'get_ip_report': get_ip_report,
    'get_ip_reputation': get_ip_reputation,
    'get_malware_reputation': get_malware_reputation,
    'get_networks_for_asn': get_networks_for_asn
}
