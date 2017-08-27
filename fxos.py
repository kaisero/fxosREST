import json
import requests
import logging
import copy

from requests.exceptions import ConnectionError
from distutils.version import LooseVersion

requests.packages.urllib3.disable_warnings()

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'pyfxos'
}


class FXOSApiException(Exception):
    pass


class FXOSAuthException(Exception):
    pass


class FXOS(object):
    def __init__(self, hostname, username, password, protocol='https', base_url='/api', auth_url='/login', logger=None,
                 verify_cert=False, timeout=30):

        self.logger = logger
        self.hostname = hostname
        self.username = username
        self.password = password
        self.protocol = protocol
        self.base_url = base_url
        self.auth_url = auth_url
        self.verify_cert = verify_cert
        self.timeout = timeout
        self.headers = copy.copy(HEADERS)
        self.headers['token'] = self._login()

    def _login(self):
        try:
            request_url = '{0}{1}'.format(self._url(), self.auth_url)
            request_headers = copy.copy(HEADERS)
            request_headers['USERNAME'] = self.username
            request_headers['PASSWORD'] = self.password
            response = requests.post(request_url, headers=request_headers, verify=self.verify_cert)
            payload = response.json()
            if 'token' not in payload:
                raise FXOSApiException('Could not retrieve token from {0}.'.format(request_url))
            if response.status_code == 400:
                if '551' in response.content:
                    raise FXOSAuthException('FX-OS API Authentication to {0} failed.'.format(self.hostname))
                if '552' in response.content:
                    raise FXOSAuthException('FX-OS API Authorization to {0} failed'.format(self.hostname))
            return payload['token']
        except ConnectionError as exc:
            self.logger.error(
                'Could not connect to {0}. Max retries exceeded with url: {1}'.format(self.hostname, request_url))
        except FXOSApiException as exc:
            self.logger.error(exc.message)
        except Exception as exc:
            self.logger.exception(exc.message)

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
            if response.status_code == 400:
                if '552' in response.content:
                    raise FXOSAuthException('FX-OS API Authorization to {0} failed'.format(self.hostname))
                if '101' in response.content:
                    raise FXOSApiException(
                        'Request {0} failed. Error communicating with FX-OS API backend.'.format(response.request))
                raise FXOSApiException('Request {0} failed with response code {1}. Eror message: {2}\nDetails: {3}'
                                       .format(response.url, response.status_code, response.reason,
                                               response.content))
        except FXOSAuthException as exc:
            self.headers['token'] = self._login()
            self.logger.error(exc.message)
        except FXOSApiException as exc:
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
        return self._patch(request, data)

    def delete_app(self, data):
        request = '/app'
        return self._delete(request, data)

    def get_app_instance(self, slot_id=None, app_id=None):
        request = '?classId=smAppInstance' if app_id is None else '/slot/{0}/app-inst/{1}'.format(slot_id, app_id)
        return self._get(request)

    def update_app_instance(self, slot_id, app_id, data):
        request = '/slot/{0}/app-inst/{1}'.format(slot_id, app_id)
        return self._patch(request, data)

    def delete_app_instance(self, slot_id, app_id):
        request = '/slot/{0}/app-inst/{1}'.format(slot_id, app_id)
        return self._delete(request)

    def set_download_app(self, data):
        request = '/sys/app-catalogue'
        return self._post(request, data)

    def update_download_app(self, data, overwrite=False):
        request = '/sys/app-catalogue'
        if overwrite:
            return self._put(request, data)
        return self._patch(request, data)

    def get_download_app(self):
        request = '/sys/app-catalogue'
        return self._get(request)

    def get_logical_device(self, id=None):
        request = '/ld' if id is None else '/ld/{0}'.format(id)
        return self._get(request)

    def set_logical_device(self, data):
        request = '/ld'
        return self._post(request, data)

    def delete_logical_device(self, id):
        request = '/ld/{0}'.format(id)
        return self._delete(request)

    def get_firmware_packages(self, id=None):
        request = '/sys/firmware/distrib' if id is None else '/sys/firmware/distrib/{0}'.format(id)
        return self._get(request)

    def get_firmware_kernel(self):
        request = '/sys/firmware/version/kernel'
        return self._get(request)

    def get_firmware_system(self):
        request = '/sys/firmware/version/system'
        return self._get(request)

    def get_firmware_path(self):
        # TODO: enhance to support different upgrade paths
        upgrade_path = ['1.1.4', '2.0.1.135', '2.1.1.64', '2.2.1.63', '2.2.1.70']
        return upgrade_path

    def get_firmware_path_for(self, current_version, new_version):
        upgrade_path_for = list()
        upgrade_path = self.get_firmware_path()
        if current_version == new_version:
            return upgrade_path_for
        for item in upgrade_path:
            if LooseVersion(current_version) < LooseVersion(item) <= LooseVersion(new_version):
                upgrade_path_for.append(item)
        return upgrade_path_for

    def get_firmware_chassis_manager(self):
        request = '/sys/firmware/version/chassis-manager'
        return self._get(request)

    def set_download_infrastructure_bundle(self, data):
        request = '/sys/firmware/dnld/{0}'.format(data['firmwareDownloader'][0]['fileName'])
        return self._post(request, data)

    def update_download_infrastructure_bundle(self, data, overwrite=False):
        request = '/sys/firmware/dnld/{0}'.format(data['firmwareDownloader'][0]['fileName'])
        if overwrite:
            return self._put(request, data)
        return self._update(request, data)

    def get_download_infrastructure_bundle(self, id):
        request = '/sys/firmware/dnld/{0}'.format(id)
        return self._get(request)

    def delete_download_infrastructure_bundle(self, id):
        request = '/sys/firmware/dnld/{0}'.format(id)
        return self._delete(request)

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

    def get_schedule_infrastructure_bundle(self):
        request = '/sys/firmware/sched-platform-fw'
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

    def get_install_infrastructure_bundle(self):
        request = '/sys/fw-system/fsm'
        return self._get(request)

    def get_mgmt_ip(self):
        request = '/sys/mgmt-ipv4'
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
        return self._patch(request, data)

    def delete_ntp_server(self, id):
        request = '/sys/service/datetime-svc/ntp/{0}'.format(id)
        return self._delete(request)

    def get_snmp_svc(self):
        request = '/sys/service/snmp-svc'
        return self._get(request)

    def update_snmp_svc(self, data):
        request = '/sys/service/snmp-svc'
        return self._patch(request, data)

    def get_snmp_trap_host(self, id=None):
        request = '/sys/service/snmp-svc/snmp-trap' if id is None else '/sys/service/snmp-svc/snmp-trap/{0}' \
            .format(id)
        return self._get(request)

    def update_snmp_trap_host(self, data):
        request = '/api/sys/service/snmp-svc/snmp-trap'
        return self._patch(request, data)

    def delete_snmp_trap_host(self, id):
        request = '/api/sys/service/snmp-svc/snmp-trap/{0}'.format(id)
        return self._delete(request)

    def get_dns_server(self, id=None):
        request = '/sys/service/dns-svc/dns' if id is None else '/sys/service/dns-svc/dns/{0}'.format(id)
        return self._get(request)

    def set_dns_server(self, data):
        request = '/sys/service/dns-svc/dns'
        return self._post(request, data)

    def delete_dns_server(self, id):
        request = '/sys/service/dns-svc/dns/{0}'.format(id)
        return self._delete(request)

    def get_syslog_svc(self):
        request = '/sys/service/syslog-svc'
        return self._get(request)

    def update_syslog_svc(self, data):
        request = '/sys/service/syslog-svc'
        return self._patch(request, data)

    def get_syslog_servcer_primary(self):
        request = 'sys/svc-ext/syslog/client-primary'
        return self._get(request)

    def update_syslog_server_primary(self, data):
        request = 'sys/svc-ext/syslog/client-primary'
        return self._patch(request, data)

    def get_syslog_server_secondary(self, data):
        request = 'sys/svc-ext/syslog/client-secondary'
        return self._get(request, data)

    def update_syslog_server_secondary(self, data):
        request = 'sys/svc-ext/syslog/client-secondary'
        return self._patch(request, data)

    def get_syslog_server_tertiary(self, data):
        request = 'sys/svc-ext/syslog/client-tertiary'
        return self._get(request, data)

    def update_syslog_server_tertiary(self, data):
        request = 'sys/svc-ext/syslog/client-tertiary'
        return self._patch(request, data)
