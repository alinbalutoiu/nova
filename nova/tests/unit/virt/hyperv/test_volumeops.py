# Copyright 2014 Cloudbase Solutions Srl
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

import mock
from os_win import exceptions as os_win_exc
from oslo_config import cfg

from nova import exception
from nova import test
from nova.tests.unit import fake_block_device
from nova.tests.unit.virt.hyperv import test_base
from nova.virt.hyperv import volumeops

CONF = cfg.CONF

connection_data = {'volume_id': 'fake_vol_id',
                   'target_lun': mock.sentinel.fake_lun,
                   'target_iqn': mock.sentinel.fake_iqn,
                   'target_portal': mock.sentinel.fake_portal,
                   'auth_method': 'chap',
                   'auth_username': mock.sentinel.fake_user,
                   'auth_password': mock.sentinel.fake_pass}


def get_fake_block_dev_info():
    return {'block_device_mapping': [
        fake_block_device.AnonFakeDbBlockDeviceDict({'source_type': 'volume'})]
    }


def get_fake_connection_info(**kwargs):
    return {'data': dict(connection_data, **kwargs),
            'serial': mock.sentinel.serial}


class VolumeOpsTestCase(test_base.HyperVBaseTestCase):
    """Unit tests for VolumeOps class."""

    def setUp(self):
        super(VolumeOpsTestCase, self).setUp()
        self._volumeops = volumeops.VolumeOps()

    def test_get_volume_driver(self):
        fake_conn_info = {'driver_volume_type': mock.sentinel.fake_driver_type}
        self._volumeops.volume_drivers[mock.sentinel.fake_driver_type] = (
            mock.sentinel.fake_driver)

        result = self._volumeops._get_volume_driver(
            connection_info=fake_conn_info)
        self.assertEqual(mock.sentinel.fake_driver, result)

    def test_get_volume_driver_exception(self):
        fake_conn_info = {'driver_volume_type': 'fake_driver'}
        self.assertRaises(exception.VolumeDriverNotFound,
                          self._volumeops._get_volume_driver,
                          connection_info=fake_conn_info)

    @mock.patch.object(volumeops.VolumeOps, 'attach_volume')
    def test_attach_volumes(self, mock_attach_volume):
        block_device_info = get_fake_block_dev_info()

        self._volumeops.attach_volumes(block_device_info,
                                       mock.sentinel.instance_name,
                                       ebs_root=True)

        mock_attach_volume.assert_called_once_with(
            block_device_info['block_device_mapping'][0]['connection_info'],
            mock.sentinel.instance_name, True)

    def test_fix_instance_volume_disk_paths_empty_bdm(self):
        with mock.patch.object(self._volumeops._vmutils,
                               'get_vm_physical_disk_mapping') as mock_get_vm:
            self._volumeops.fix_instance_volume_disk_paths(
                mock.sentinel.instance_name,
                block_device_info='')
            self.assertFalse(mock_get_vm.called)

    def test_fix_instance_volume_disk_paths(self):
        block_device_info = get_fake_block_dev_info()
        mock_disk_path = {
            'mounted_disk_path': mock.sentinel.mounted_disk_path,
            'resource_path': mock.sentinel.resource_path
        }
        fake_phys_disk_path_mapping = {
            mock.sentinel.virtual_disk_res: mock_disk_path,
            mock.sentinel.another_virtual_disk_res: mock_disk_path
        }

        fake_actual_disk_mapping = {
            'serial': mock.sentinel.actual_disk_path
        }

        with mock.patch.object(
            self._volumeops, 'get_disk_path_mapping') as (
                mock_get_disk_path_mapping):

            vmutils = self._volumeops._vmutils
            vmutils.get_vm_physical_disk_mapping.return_value = (
                fake_phys_disk_path_mapping)

            mock_get_disk_path_mapping.return_value = fake_actual_disk_mapping

            self._volumeops.fix_instance_volume_disk_paths(
                mock.sentinel.instance_name,
                block_device_info)

            expected_calls = [
                mock.call(mock.sentinel.resource_path,
                          mock.sentinel.actual_disk_path)] * 2

            vmutils.get_vm_physical_disk_mapping.assert_called_once_with(
                mock.sentinel.instance_name)
            mock_get_disk_path_mapping.assert_called_once_with(
                block_device_info)
            vmutils.set_disk_host_resource.assert_has_calls(expected_calls)

    @mock.patch.object(volumeops.VolumeOps, '_get_volume_driver')
    def test_disconnect_volumes(self, mock_get_volume_driver):
        block_device_info = get_fake_block_dev_info()
        block_device_mapping = block_device_info['block_device_mapping']
        block_device_mapping[0]['connection_info'] = {
            'driver_volume_type': mock.sentinel.fake_vol_type}
        fake_volume_driver = mock_get_volume_driver.return_value

        self._volumeops.disconnect_volumes(block_device_info)
        fake_volume_driver.disconnect_volumes.assert_called_once_with(
            block_device_mapping)

    @mock.patch('nova.block_device.volume_in_mapping')
    def test_ebs_root_in_block_devices(self, mock_vol_in_mapping):
        block_device_info = get_fake_block_dev_info()

        response = self._volumeops.ebs_root_in_block_devices(block_device_info)

        mock_vol_in_mapping.assert_called_once_with(
            self._volumeops._default_root_device, block_device_info)
        self.assertEqual(mock_vol_in_mapping.return_value, response)

    @mock.patch.object(volumeops.ISCSIVolumeDriver, 'initiator')
    @mock.patch.object(volumeops.BaseVolumeDriver,
                       'get_volume_connector_props')
    def test_get_volume_connector(self, mock_base_get_vol_connector_props,
                                  mock_ISCSI_initiator):
        mock_instance = mock.DEFAULT
        initiator = mock_ISCSI_initiator
        expected = {'ip': CONF.my_ip,
                    'host': CONF.host,
                    'initiator': initiator,
                    'wwnns': [],
                    'wwpns': []}

        response = self._volumeops.get_volume_connector(instance=mock_instance)

        mock_base_get_vol_connector_props.assert_called_once_with()
        self.assertEqual(expected, response)

    @mock.patch.object(volumeops.VolumeOps, '_get_volume_driver')
    def test_initialize_volumes_connection(self, mock_get_volume_driver):
        block_device_info = get_fake_block_dev_info()

        self._volumeops.initialize_volumes_connection(block_device_info)

        init_vol_conn = (
            mock_get_volume_driver.return_value.initialize_volume_connection)
        init_vol_conn.assert_called_once_with(
            block_device_info['block_device_mapping'][0]['connection_info'])

    @mock.patch.object(volumeops.VolumeOps, '_get_volume_driver')
    def test_get_disk_path_mapping(self, mock_get_volume_driver):
        block_device_info = get_fake_block_dev_info()
        block_device_mapping = block_device_info['block_device_mapping']
        block_device_mapping[0]['connection_info'] = get_fake_connection_info()
        fake_vol_conn_info = (
            block_device_info['block_device_mapping'][0]['connection_info'])

        fake_vol_driver = mock_get_volume_driver.return_value

        resulted_disk_path_mapping = self._volumeops.get_disk_path_mapping(
            block_device_info)

        mock_get_volume_driver.assert_called_once_with(
            connection_info=fake_vol_conn_info)
        get_mounted_disk = fake_vol_driver.get_mounted_disk_path_from_volume
        get_mounted_disk.assert_called_once_with(fake_vol_conn_info)
        expected_disk_path_mapping = {
            fake_vol_conn_info['serial']: get_mounted_disk.return_value}
        self.assertEqual(expected_disk_path_mapping,
                         resulted_disk_path_mapping)

    def test_group_block_devices_by_type(self):
        block_device_map = get_fake_block_dev_info()['block_device_mapping']
        block_device_map[0]['connection_info'] = {
            'driver_volume_type': 'iscsi'}
        result = self._volumeops._group_block_devices_by_type(
            block_device_map)

        expected = {'iscsi': [block_device_map[0]]}
        self.assertEqual(expected, result)

    @mock.patch.object(volumeops.VolumeOps, '_get_volume_driver')
    def test_get_mounted_disk_path_from_volume(self, mock_get_volume_driver):
        fake_conn_info = get_fake_connection_info()
        fake_volume_driver = mock_get_volume_driver.return_value

        resulted_disk_path = self._volumeops.get_mounted_disk_path_from_volume(
            fake_conn_info)

        mock_get_volume_driver.assert_called_once_with(
            connection_info=fake_conn_info)
        get_mounted_disk = fake_volume_driver.get_mounted_disk_path_from_volume
        get_mounted_disk.assert_called_once_with(fake_conn_info)
        self.assertEqual(get_mounted_disk.return_value,
                         resulted_disk_path)


class TestBaseVolumeDriver(test_base.HyperVBaseTestCase):
    """Unit tests for Hyper-V BaseVolumeDriver class."""

    def setUp(self):
        super(TestBaseVolumeDriver, self).setUp()
        mock_abstract_methods = mock.patch.multiple(volumeops.BaseVolumeDriver,
                                                    __abstractmethods__=set())
        mock_abstract_methods.start()
        self._base_vol_driver = volumeops.BaseVolumeDriver()
        self._base_vol_driver._vmutils = mock.MagicMock()

    @mock.patch.object(volumeops.BaseVolumeDriver,
                       'get_mounted_disk_path_from_volume')
    @mock.patch.object(volumeops.BaseVolumeDriver, '_get_disk_ctrl_and_slot')
    @mock.patch.object(volumeops.BaseVolumeDriver, 'disconnect_volumes')
    def _check_attach_volume(self, mock_disconnect_volumes,
                             mock_get_disk_ctrl_and_slot,
                             mock_get_mounted_disk_path_from_volume,
                             physical_disk_drives=True,
                             raised_exception=None):
        connection_info = get_fake_connection_info()
        self._base_vol_driver._physical_disk_drives = physical_disk_drives
        vmutils = self._base_vol_driver._vmutils

        fake_mounted_disk_path = (
            mock_get_mounted_disk_path_from_volume.return_value)
        mock_get_disk_ctrl_and_slot.return_value = (
            mock.sentinel.ctrller_path,
            mock.sentinel.slot)
        vmutils.attach_volume_to_controller.side_effect = raised_exception

        if raised_exception and physical_disk_drives:
            self.assertRaises(raised_exception,
                              self._base_vol_driver.attach_volume,
                              connection_info,
                              mock.sentinel.instance_name,
                              mock.sentinel.ebs_root)
            mock_disconnect_volumes([connection_info])
        else:
            self._base_vol_driver.attach_volume(
                connection_info=connection_info,
                instance_name=mock.sentinel.instance_name,
                ebs_root=mock.sentinel.ebs_root)

        if physical_disk_drives:
            vmutils.attach_volume_to_controller.assert_called_once_with(
                mock.sentinel.instance_name,
                mock.sentinel.ctrller_path,
                mock.sentinel.slot,
                fake_mounted_disk_path,
                serial=connection_info['serial'])
        else:
            vmutils.attach_drive.assert_called_once_with(
                mock.sentinel.instance_name,
                fake_mounted_disk_path,
                mock.sentinel.ctrller_path,
                mock.sentinel.slot)

        mock_get_mounted_disk_path_from_volume.assert_called_once_with(
            connection_info)
        mock_get_disk_ctrl_and_slot.assert_called_once_with(
            mock.sentinel.instance_name, mock.sentinel.ebs_root)

    def test_attach_volume_fails(self):
        self._check_attach_volume(raised_exception=Exception)

    def test_attach_volume_drive(self):
        self._check_attach_volume()

    @mock.patch.object(volumeops.BaseVolumeDriver,
                       'get_mounted_disk_path_from_volume')
    @mock.patch.object(volumeops.BaseVolumeDriver, 'disconnect_volumes')
    def test_detach_volume(self, mock_disconnect_volumes,
                           mock_get_mounted_disk_path_from_volume):
        connection_info = get_fake_connection_info()

        self._base_vol_driver.detach_volume(connection_info,
                                            mock.sentinel.instance_name)

        mock_get_mounted_disk_path_from_volume.assert_called_once_with(
            connection_info)
        self._base_vol_driver._vmutils.detach_vm_disk.assert_called_once_with(
            mock.sentinel.instance_name,
            mock_get_mounted_disk_path_from_volume.return_value,
            is_physical=self._base_vol_driver._physical_disk_drives)
        mock_disconnect_volumes.assert_called_once_with([connection_info])

    def _test_get_disk_ctrl_and_slot(self, ebs_root=True):
        resulted_ctrl_and_slot = self._base_vol_driver._get_disk_ctrl_and_slot(
            mock.sentinel.instance_name,
            ebs_root)

        vmutils = self._base_vol_driver._vmutils
        if ebs_root:
            expected_ctrl_and_slot = (
                vmutils.get_vm_ide_controller.return_value, 0)

            vmutils.get_vm_ide_controller.assert_called_once_with(
                mock.sentinel.instance_name, 0)
        else:
            expected_ctrl_and_slot = (
                vmutils.get_vm_scsi_controller.return_value,
                vmutils.get_free_controller_slot.return_value)

            vmutils.get_vm_scsi_controller.assert_called_once_with(
                mock.sentinel.instance_name)
            vmutils.get_free_controller_slot(
                vmutils.get_vm_scsi_controller.return_value)

        self.assertEqual(expected_ctrl_and_slot, resulted_ctrl_and_slot)

    def test_get_disk_ctrl_and_slot_IDE(self):
        self._test_get_disk_ctrl_and_slot()

    def test_get_disk_ctrl_and_slot_SCSI(self):
        self._test_get_disk_ctrl_and_slot(ebs_root=False)


class ISCSIVolumeDriverTestCase(test_base.HyperVBaseTestCase):
    """Unit tests for Hyper-V ISCSIVolumeDriver class."""

    def setUp(self):
        super(ISCSIVolumeDriverTestCase, self).setUp()
        self._volume_driver = volumeops.ISCSIVolumeDriver()
        self._volume_driver._vmutils = mock.MagicMock()
        self._volume_driver._volutils = mock.MagicMock()

    def test_initiator(self):
        resulted_initiator = self._volume_driver.initiator

        _volutils = self._volume_driver._volutils
        _volutils.get_iscsi_initiator.assert_called_once_with()
        expected_init = _volutils.get_iscsi_initiator.return_value
        self.assertEqual(expected_init, resulted_initiator)

    def _test_get_volume_connector_props(self, initiator_valid=True):
        self._volume_driver._volutils.get_iscsi_initiator.return_value = None
        self._volume_driver._initiator = (
            mock.sentinel.initiator if initiator_valid else None)

        resulted_props = self._volume_driver.get_volume_connector_props()

        expected_props = (
            {'initiator': mock.sentinel.initiator} if initiator_valid else {})

        self.assertEqual(expected_props, resulted_props)

    def test_get_vol_connector_props(self):
        self._test_get_volume_connector_props()

    def test_get_vol_connector_props_without_initiator(self):
        self._test_get_volume_connector_props(initiator_valid=False)

    def test_login_storage_target_auth_exception(self):
        connection_info = get_fake_connection_info(
            auth_method='fake_auth_method')

        self.assertRaises(exception.UnsupportedBDMVolumeAuthMethod,
                          self._volume_driver.login_storage_target,
                          connection_info)

    @mock.patch.object(volumeops.ISCSIVolumeDriver,
                       '_get_mounted_disk_from_lun')
    def _check_login_storage_target(self, mock_get_mounted_disk_from_lun,
                                    dev_number):
        connection_info = get_fake_connection_info()
        login_target = self._volume_driver._volutils.login_storage_target
        get_number = self._volume_driver._volutils.get_device_number_for_target
        get_number.return_value = dev_number

        self._volume_driver.login_storage_target(connection_info)

        get_number.assert_called_once_with(mock.sentinel.fake_iqn,
                                           mock.sentinel.fake_lun)
        if not dev_number:
            login_target.assert_called_once_with(
                mock.sentinel.fake_lun, mock.sentinel.fake_iqn,
                mock.sentinel.fake_portal, mock.sentinel.fake_user,
                mock.sentinel.fake_pass)
            mock_get_mounted_disk_from_lun.assert_called_once_with(
                mock.sentinel.fake_iqn, mock.sentinel.fake_lun, True)
        else:
            self.assertFalse(login_target.called)

    def test_login_storage_target_already_logged(self):
        self._check_login_storage_target(dev_number=1)

    def test_login_storage_target(self):
        self._check_login_storage_target(dev_number=0)

    def _check_logout_storage_target(self, disconnected_luns_count=0):
        self._volume_driver._volutils.get_target_lun_count.return_value = 1

        self._volume_driver.logout_storage_target(
            target_iqn=mock.sentinel.fake_iqn,
            disconnected_luns_count=disconnected_luns_count)

        logout_storage = self._volume_driver._volutils.logout_storage_target

        if disconnected_luns_count:
            logout_storage.assert_called_once_with(mock.sentinel.fake_iqn)
        else:
            self.assertFalse(logout_storage.called)

    def test_logout_storage_target_skip(self):
        self._check_logout_storage_target()

    def test_logout_storage_target(self):
        self._check_logout_storage_target(disconnected_luns_count=1)

    @mock.patch.object(volumeops.ISCSIVolumeDriver,
                       '_get_mounted_disk_from_lun')
    def test_get_mounted_disk_path_from_volume(self,
                                               mock_get_mounted_disk_from_lun):
        connection_info = get_fake_connection_info()
        resulted_disk_path = (
            self._volume_driver.get_mounted_disk_path_from_volume(
                connection_info))

        mock_get_mounted_disk_from_lun.assert_called_once_with(
            connection_info['data']['target_iqn'],
            connection_info['data']['target_lun'],
            wait_for_device=True)
        self.assertEqual(mock_get_mounted_disk_from_lun.return_value,
                         resulted_disk_path)

    def test_get_mounted_disk_from_lun(self):
        with test.nested(
            mock.patch.object(self._volume_driver._volutils,
                              'get_device_number_for_target'),
            mock.patch.object(self._volume_driver._vmutils,
                              'get_mounted_disk_by_drive_number')
            ) as (mock_get_device_number_for_target,
                  mock_get_mounted_disk_by_drive_number):

            mock_get_device_number_for_target.return_value = 0
            mock_get_mounted_disk_by_drive_number.return_value = (
                mock.sentinel.disk_path)

            disk = self._volume_driver._get_mounted_disk_from_lun(
                mock.sentinel.target_iqn,
                mock.sentinel.target_lun)
            self.assertEqual(mock.sentinel.disk_path, disk)

    def test_get_target_from_disk_path(self):
        result = self._volume_driver.get_target_from_disk_path(
            mock.sentinel.physical_drive_path)

        mock_get_target = (
            self._volume_driver._volutils.get_target_from_disk_path)
        mock_get_target.assert_called_once_with(
            mock.sentinel.physical_drive_path)
        self.assertEqual(mock_get_target.return_value, result)

    @mock.patch('time.sleep')
    def test_get_mounted_disk_from_lun_failure(self, fake_sleep):
        self.flags(mounted_disk_query_retry_count=1, group='hyperv')

        with mock.patch.object(self._volume_driver._volutils,
                               'get_device_number_for_target') as m_device_num:
            m_device_num.side_effect = [None, -1]

            self.assertRaises(exception.NotFound,
                              self._volume_driver._get_mounted_disk_from_lun,
                              mock.sentinel.target_iqn,
                              mock.sentinel.target_lun)

    @mock.patch.object(volumeops.ISCSIVolumeDriver, 'logout_storage_target')
    def test_disconnect_volumes(self, mock_logout_storage_target):
        block_device_info = get_fake_block_dev_info()
        connection_info = get_fake_connection_info()
        block_device_mapping = block_device_info['block_device_mapping']
        block_device_mapping[0]['connection_info'] = connection_info

        self._volume_driver.disconnect_volumes(block_device_mapping)

        mock_logout_storage_target.assert_called_once_with(
            mock.sentinel.fake_iqn, 1)

    def test_get_target_lun_count(self):
        result = self._volume_driver.get_target_lun_count(
            mock.sentinel.target_iqn)

        mock_get_lun_count = self._volume_driver._volutils.get_target_lun_count
        mock_get_lun_count.assert_called_once_with(mock.sentinel.target_iqn)
        self.assertEqual(mock_get_lun_count.return_value, result)

    @mock.patch.object(volumeops.ISCSIVolumeDriver, 'login_storage_target')
    def test_initialize_volume_connection(self, mock_login_storage_target):
        self._volume_driver.initialize_volume_connection(
            mock.sentinel.connection_info)
        mock_login_storage_target.assert_called_once_with(
            mock.sentinel.connection_info)


class SMBFSVolumeDriverTestCase(test_base.HyperVBaseTestCase):
    """Unit tests for the Hyper-V SMBFSVolumeDriver class."""

    _FAKE_SHARE = '//1.2.3.4/fake_share'
    _FAKE_SHARE_NORMALIZED = _FAKE_SHARE.replace('/', '\\')
    _FAKE_DISK_NAME = 'fake_volume_name.vhdx'
    _FAKE_USERNAME = 'fake_username'
    _FAKE_PASSWORD = 'fake_password'
    _FAKE_SMB_OPTIONS = '-o username=%s,password=%s' % (_FAKE_USERNAME,
                                                        _FAKE_PASSWORD)
    _FAKE_CONNECTION_INFO = {'data': {'export': _FAKE_SHARE,
                                      'name': _FAKE_DISK_NAME,
                                      'options': _FAKE_SMB_OPTIONS,
                                      'volume_id': 'fake_vol_id'}}

    def setUp(self):
        super(SMBFSVolumeDriverTestCase, self).setUp()
        self._volume_driver = volumeops.SMBFSVolumeDriver()
        self._volume_driver._vmutils = mock.MagicMock()
        self._volume_driver._pathutils = mock.MagicMock()
        self._volume_driver._volutils = mock.MagicMock()

    def test_get_mounted_disk_path_from_volume(self):
        connection_info = get_fake_connection_info()
        connection_info['data']['export'] = self._FAKE_SHARE
        connection_info['data']['name'] = self._FAKE_DISK_NAME
        vol_driver = self._volume_driver
        resulted_disk_path = vol_driver.get_mounted_disk_path_from_volume(
            connection_info)
        expected_export = os.path.join(self._FAKE_SHARE.replace('/', '\\'),
                                       self._FAKE_DISK_NAME)
        self.assertEqual(expected_export, resulted_disk_path)

    def test_parse_credentials(self):
        username, password = self._volume_driver._parse_credentials(
            self._FAKE_SMB_OPTIONS)
        self.assertEqual(self._FAKE_USERNAME, username)
        self.assertEqual(self._FAKE_PASSWORD, password)

    def test_get_export_path(self):
        result = self._volume_driver._get_export_path(
            self._FAKE_CONNECTION_INFO)

        expected = self._FAKE_SHARE.replace('/', '\\')
        self.assertEqual(expected, result)

    def test_get_disk_path(self):
        expected = os.path.join(self._FAKE_SHARE_NORMALIZED,
                                self._FAKE_DISK_NAME)

        disk_path = self._volume_driver._get_disk_path(
            self._FAKE_CONNECTION_INFO)

        self.assertEqual(expected, disk_path)

    @mock.patch.object(volumeops.SMBFSVolumeDriver, '_parse_credentials')
    def _test_ensure_mounted(self, mock_parse_credentials, is_mounted=False):
        mock_mount_smb_share = self._volume_driver._pathutils.mount_smb_share
        self._volume_driver._pathutils.check_smb_mapping.return_value = (
            is_mounted)
        mock_parse_credentials.return_value = (
            self._FAKE_USERNAME, self._FAKE_PASSWORD)

        self._volume_driver.ensure_share_mounted(
            self._FAKE_CONNECTION_INFO)

        if is_mounted:
            self.assertFalse(
                mock_mount_smb_share.called)
        else:
            mock_mount_smb_share.assert_called_once_with(
                self._FAKE_SHARE_NORMALIZED,
                username=self._FAKE_USERNAME,
                password=self._FAKE_PASSWORD)

    def test_ensure_mounted_new_share(self):
        self._test_ensure_mounted()

    def test_ensure_already_mounted(self):
        self._test_ensure_mounted(is_mounted=True)

    def test_disconnect_volumes(self):
        block_device_mapping = [
            {'connection_info': self._FAKE_CONNECTION_INFO}]
        self._volume_driver.disconnect_volumes(block_device_mapping)
        mock_unmount_share = self._volume_driver._pathutils.unmount_smb_share
        mock_unmount_share.assert_called_once_with(
            self._FAKE_SHARE_NORMALIZED)


class FCVolumeDriverTestCase(test_base.HyperVBaseTestCase):
    def setUp(self):
        super(FCVolumeDriverTestCase, self).setUp()
        self._fc_driver = volumeops.FCVolumeDriver()
        self._fc_driver._fc_utils = mock.MagicMock()
        self._fc_driver._vmutils = mock.MagicMock()

        self._fc_utils = self._fc_driver._fc_utils
        self._vmutils = self._fc_driver._vmutils

    def _test_get_volume_connector_props(self, valid_fc_hba_ports=True):
        fake_fc_hba_ports = [{'node_name': mock.sentinel.node_name,
                              'port_name': mock.sentinel.port_name},
                             {'node_name': mock.sentinel.second_node_name,
                              'port_name': mock.sentinel.second_port_name}]
        self._fc_utils.get_fc_hba_ports.return_value = (
            fake_fc_hba_ports if valid_fc_hba_ports else None)

        resulted_fc_hba_ports = self._fc_driver.get_volume_connector_props()

        self._fc_utils.refresh_hba_configuration.assert_called_once_with()
        self._fc_utils.get_fc_hba_ports.assert_called_once_with()
        expected_fc_hba_ports = {
            'wwpns': [mock.sentinel.port_name, mock.sentinel.second_port_name],
            'wwnns': [mock.sentinel.node_name, mock.sentinel.second_node_name]
        }
        if valid_fc_hba_ports:
            self.assertEqual(set(expected_fc_hba_ports),
                             set(resulted_fc_hba_ports))
        else:
            self.assertEqual({}, resulted_fc_hba_ports)

    def test_get_volume_connector_props(self):
        self._test_get_volume_connector_props()

    def test_get_volume_connector_props_empty(self):
        self._test_get_volume_connector_props(valid_fc_hba_ports=False)

    @mock.patch.object(volumeops.FCVolumeDriver, '_get_fc_hba_mapping')
    def _test_get_mounted_disk_path_from_volume(self, mock_get_fc_hba_mapping,
                                                device_names_found=True):
        mock_target_wwpns = [mock.sentinel.port_name]

        mock_initiator_map = mock.MagicMock()
        connection_info = get_fake_connection_info(
            initiator_target_map=mock_initiator_map,
            target_lun=mock.sentinel.target_lun,
            target_wwn=mock_target_wwpns)
        mock_target_mappings = [{'device_name': mock.sentinel.device_name,
                                 'port_name': mock.sentinel.port_name,
                                 'lun': mock.sentinel.target_lun}]
        fake_hba_ports = [mock.sentinel.port_name,
                          mock.sentinel.second_port_name]

        mock_initiator_map.return_value = device_names_found
        self._fc_utils.get_fc_target_mappings.return_value = (
            mock_target_mappings)
        fake_hba_mapping = {mock.sentinel.node_name: fake_hba_ports}
        mock_get_fc_hba_mapping.return_value = (
            fake_hba_mapping if device_names_found else {})

        if device_names_found:
            resulted_mounted_disk_path = (
                self._fc_driver.get_mounted_disk_path_from_volume(
                    connection_info))

            expected_mounted_disk_path = (
                self._vmutils.get_mounted_disk_by_drive_number.return_value)
            self.assertEqual(expected_mounted_disk_path,
                             resulted_mounted_disk_path)

            expected_initiator_map_get_call_count = len(fake_hba_ports)
            self.assertEqual(expected_initiator_map_get_call_count,
                             mock_initiator_map.get.call_count)
            self._fc_utils.get_fc_target_mappings.assert_called_once_with(
                mock.sentinel.node_name)
            mock_get_fc_hba_mapping.assert_called_once_with()
        else:
            self.assertRaises(
                exception.DiskNotFound,
                self._fc_driver.get_mounted_disk_path_from_volume,
                connection_info)

            expected_calls_count = 11
            self.assertEqual(expected_calls_count,
                             self._fc_utils.rescan_disks.call_count)
            self.assertEqual(expected_calls_count,
                             mock_get_fc_hba_mapping.call_count)

    def test_get_mounted_disk_path_from_vol(self):
        self._test_get_mounted_disk_path_from_volume()

    def test_get_mounted_disk_path_from_vol_without_devices(self):
        self._test_get_mounted_disk_path_from_volume(
            device_names_found=False)

    def test_get_fc_hba_mapping(self):
        fake_fc_hba_ports = [{'node_name': mock.sentinel.node_name,
                              'port_name': mock.sentinel.port_name}]

        self._fc_utils.get_fc_hba_ports.return_value = fake_fc_hba_ports

        resulted_mapping = self._fc_driver._get_fc_hba_mapping()

        expected_mapping = volumeops.collections.defaultdict(list)
        expected_mapping[mock.sentinel.node_name].append(
            mock.sentinel.port_name)
        self.assertEqual(expected_mapping, resulted_mapping)
