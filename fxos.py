import json
import requests
import logging
import sys
import copy

from rainbow_logging_handler import RainbowLoggingHandler
from requests.exceptions import ConnectionError
from pprint import pprint

requests.packages.urllib3.disable_warnings()

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'pyfxos'
}


class apiException(Exception):
    pass


class FXOS(object):
    def __init__(self, hostname, username, password, protocol='https', base_url='/api', auth_url='/login', logger=None,
                 loglevel=logging.INFO, verify_cert=False, timeout=30):

        self.logger = self._get_logger(logger, loglevel)
        self.hostname = hostname
        self.username = username
        self.password = password
        self.protocol = protocol
        self.base_url = base_url
        self.auth_url = auth_url
        self.verify_cert = verify_cert
        self.timeout = timeout
        self.headers = HEADERS
        self.headers['token'] = self._login()

    def _get_logger(self, logger, loglevel):
        """
        Get a (new) logger instance
        :param loglevel: desired loglevel
        :return: logger instance
        """
        if logger is None:
            logger = logging.getLogger(__name__)
            handler = RainbowLoggingHandler(sys.stderr, color_funcName=('black', 'yellow', True))
            formatter = logging.Formatter('[%(asctime)s] (%(levelname)s) [%(name)s] %(message)s')

            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(loglevel)
            return logger
        return self.logger

    def _login(self):
        try:
            request_url = '{0}{1}'.format(self._url(), self.auth_url)
            request_headers = copy.copy(HEADERS)
            request_headers['USERNAME'] = self.username
            request_headers['PASSWORD'] = self.password
            response = requests.post(request_url, headers=request_headers, verify=self.verify_cert)
            payload = response.json()
            if 'token' not in payload:
                raise apiException('Could not retrieve token from {0}.'.format(request_url))
            if response.status_code == 400:
                if '551' in response.content:
                    raise apiException('FX-OS API Authentication to {0} failed.'.format(self.hostname))
                if '552' in response.content:
                    raise apiException('FX-OS API Authorization to {0} failed'.format(self.hostname))
            return payload['token']
        except ConnectionError as exc:
            self.logger.error(
                'Could not connect to {0}. Max retries exceeded with url: {1}'.format(self.hostname, request_url))
        except apiException as exc:
            self.logger.error(exc.message)
        except Exception as exc:
            self.logger.debug(exc.message)

    def _url(self):
        return '{0}://{1}{2}'.format(self.protocol, self.hostname, self.base_url)

    def _delete(self, request, headers=None):
        url = '{0}{1}'.format(self._url(), request)
        headers = self.headers if headers is None else headers
        response = requests.delete(url, headers=headers, verify=self.verify_cert, timeout=self.timeout)
        return self._validate(response)

    def _get(self, request, headers=None):
        url = '{0}{1}'.format(self._url(), request)
        headers = self.headers if headers is None else headers
        response = requests.get(url, headers=headers, verify=self.verify_cert, timeout=self.timeout)
        return self._validate(response)

    def _patch(self, request, data, headers=None):
        url = '{0}{1}'.format(self._url(), request)
        headers = self.headers if headers is None else headers
        response = requests.patch(url, data=json.dumps(data), headers=headers, verify=self.verify_cert,
                                  timeout=self.timeout)
        return self._validate(response)

    def _put(self, request, data, headers=None):
        url = '{0}{1}'.format(self._url(), request)
        headers = self.headers if headers is None else headers
        response = requests.put(url, data=json.dumps(data), headers=headers, verify=self.verify_cert,
                                timeout=self.timeout)
        return self._validate(response)

    def _post(self, request, data=False, headers=None):
        url = '{0}{1}'.format(self._url(), request)
        headers = self.headers if headers is None else headers
        if data:
            response = requests.post(url, data=json.dumps(data), headers=headers, verify=self.verify_cert,
                                     timeout=self.timeout)
        else:
            response = requests.post(url, headers=headers, verify=self.verify_cert, timeout=self.timeout)
        return self._validate(response)

    def _validate(self, response):
        try:
            if response.status_code > 399:
                raise apiException('Request {0} failed with response code {1}. Eror message: {2}'
                                   .format(response.request, response.status_code, response.text))
        except apiException as exc:
            self.logger.error(exc.message)
        finally:
            return response

    def get_physical_interface(self, id=None):
        request = '/ports/ep' if id is None else '/ports/ep/{0}'.format(id.replace('/', '_API_SLASH_'))
        return self._get(request)

    def get_portchannel_interface(self, id=None):
        request = '/ports/pc' if id is None else '/ports/pc/{0}'.format(id)
        return self._get(request)

    def set_portchannel_interface(self, data):
        request = '/ports/pc'
        return self._post(request, data)

    def update_portchannel_interface(self, data):
        request = '/ports/pc'
        return self._patch(request, data)

    def delete_portchannel_interface(self, data):
        request = '/ports/pc'
        return self._delete(request, data)

    def get_slot(self, id=None):
        request = '/slot' if id is None else '/slot/{0}'.format(id)
        return self._get(request)

    def update_slot(self, id=None):
        request = '/slot' if id is None else '/slot/{0}'.format(id)
        return self._patch(request)

    def get_app(self, id=None):
        request = '/app' if id is None else '/app/{0}'.format(id)
        return self._get(request)

    def update_app(self, data):
        request = '/app'
        return self._patch(request)

    def delete_app(self, data):
        request = '/app'
        return self._delete(request)

    def get_app_instance(self, slot_id=None, app_id=None):
        request = '?classId=smAppInstance' if app_id is None else '/slot/{0}/app-inst/{1}'.format(slot_id, app_id)
        return self._get(request)

    def update_app_instance(self, slot_id, app_id, data):
        request = '/slot/{0}/app-inst/{1}'.format(slot_id, app_id)
        return self._patch(request)

    def delete_app_instance(self, slot_id, app_id):
        request = '/slot/{0}/app-inst/{1}'.format(slot_id, app_id)
        return self._delete(request)

    def download_app(self, data):
        request = '/sys/app-catalogue'
        return self._post(request)

    def get_logical_device(self, id=None):
        request = '/ld' if id is None else '/ld/{0}'.format(id)
        return self._get(request)

    def set_logical_device(self, data):
        request = '/ld'
        return self._post(request, data)

    def delete_logical_device(self, id):
        request = '/ld/{0}'.format(id)
        return self._delete(request)

    def download_infrastructure_bundle(self, data):
        request = '/platformDownloader/{0}'.format(data['firmwareDownloader']['fileName'])
        return self._post(request)

    def status_download_infrastructure_bundle(self, id):
        request = '/platformDownloader/{0}'.format(id)
        return self._get(request)

    def get_infrastructure_bundle(self, id=None):
        request = '/sys/firmware/distrib' if id is None else '/sys/firmware/distrib/{0}'.format(id)
        return self._get(request)

    def update_infrastructure_bundle(self, data, id=None):
        request = '/sys/firmware/distrib' if id is None else '/sys/firmware/distrib/{0}'.format(id)
        return self._patch(request, data)

    def validate_infrastracture_bundle(self, id=None):
        request = '/sys/firmware/validate-platform-fw' if id is None else '/sys/firmware/validate-platform-fw/{0}' \
            .format(id)
        return self._get(request)

    def schedule_infrastructure_bundle(self, data):
        request = '/sys/firmware/sched-platform-fw'
        return self._patch(request, data)

    def install_infrastructure_bundle(self, data):
        request = '/sys/firmware/sched-platform-fw'
        return self._patch(request, data)

    def cancel_install_infrastructure_bundle(self, data):
        request = '/sys/firmware/cancel-platform-fw'
        return self._patch(request, data)

    def status_install_infrastructure_bundle(self):
        request = '/sys/firmware/sched-platform-fw'
        return self._get(request)

    def get_mgmt_ip(self):
        request = '/api/sys/mgmt-ipv4'
        return self._get(request)

    def update_mgmt_ip(self, data):
        request = '/sys/mgmt-ipv4'
        return self._patch(request, data)

    def get_mgmt_ipv6(self):
        request = '/sys/mgmt-ipv6'
        return self._get(request)

    def update_mgmt_ipv6(self, data):
        request = '/sys/mgmt-ipv6'
        return self._patch(request, data)

    def get_ntp_svc(self):
        request = '/sys/service/datetime-svc'
        return self._get(request)

    def update_ntp_svc(self):
        request = '/sys/service/datetime-svc'
        return self._patch(request)

    def get_ntp_server(self, id=None):
        request = '/sys/service/datetime-svc/ntp' if id is None else '/sys/service/datetime-svc/ntp/{0}'.format(id)
        return self._get(request)

    def set_ntp_server(self, data):
        request = '/sys/service/datetime-svc/ntp'
        return self._post(request, data)

    def update_ntp_server(self, data, id=None):
        request = '/sys/service/datetime-svc/ntp' if id is None else '/sys/service/datetime-svc/ntp/{0}'.format(id)
        self._patch(request, data)

    def get_snmp_svc(self):
        request = '/sys/svc-ext/snmp-svc'
        self._get(request)

    def update_snmp_svc(self, data):
        request = '/sys/svc-ext/snmp-svc'
        self._patch(request, data)

    def get_snmp_trap_host(self, data, id=None):
        request = '/sys/service/snmp-svc/snmp-trap' if id is None else '/sys/service/snmp-svc/snmp-trap/{0}' \
            .format(id)
        self._get(request)

    def update_snmp_trap_host(self, data):
        request = '/api/sys/service/snmp-svc/snmp-trap'
        self._patch(request)

    def get_dns_server(self, id=None):
        request = '/sys/service/dns-svc/dns' if id is None else '/sys/service/dns-svc/dns/{0}'.format(id)
        self._get(request)

    def set_dns_server(self, data):
        request = '/sys/service/dns-svc/dns'
        self._post(request)

    def update_dns_server(self, data):
        request = '/sys/service/dns-svc/dns'
        self._patch(request)

    def delete_dns_server(self, id):
        request = '/sys/service/dns-svc/dns/{0}'.join(id)
        self._delete(request)

    def get_syslog_svc(self):
        request = '/sys/service/syslog-svc'
        self._get(request)

    def update_syslog_svc(self, data):
        request = '/sys/service/syslog-svc'
        self._update(request, data)

    def update_syslog_server_primary(self, data):
        request = 'sys/svc-ext/syslog/client-primary'
        self._update(request, data)

    def update_syslog_server_primary(self, data):
        request = 'sys/svc-ext/syslog/client-primary'
        self._update(request, data)

    def update_syslog_server_secondary(self, data):
        request = 'sys/svc-ext/syslog/client-secondary'
        self._update(request, data)

    def update_syslog_server_tertiary(self, data):
        request = 'sys/svc-ext/syslog/client-tertiary'
        self._update(request, data)
