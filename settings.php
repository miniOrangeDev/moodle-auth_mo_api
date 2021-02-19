<?php
// This file is part of miniOrange moodle plugin
//
// This plugin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * This library is contain overridden moodle method.
 *
 * Contains authentication method.
 *
 * @copyright   2020  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     auth_mo_api
 */
defined('MOODLE_INTERNAL') || die;
if ($ADMIN->fulltree) {
	global $CFG;
	$config = get_config('auth/mo_api');
    if(empty($apikey))
	{
	    $apikey = "abcd";
	    set_config('apikey', $apikey, 'auth/mo_api');
	}

	$settings->add(new admin_setting_heading('auth_mo_api/pluginname','',
			new lang_string('auth_mo_configure_api_setting', 'auth_mo_api'),
            new lang_string('mo_apidescription', 'auth_mo_api')));

	//API Credentials

	$settings->add(new admin_setting_heading('auth_mo_api/api_credentials',
            new lang_string('mo_api_credentials', 'auth_mo_api'), ''));

	$settings->add(new admin_setting_description('auth_mo_api/User_Authentication_API_URL',
            new lang_string('mo_api_User_Authentication_API_URL', 'auth_mo_api'),
            $CFG->wwwroot."/auth/mo_api/api.php"));

	$settings->add(new admin_setting_description('auth_mo_api/API_key',
            new lang_string('mo_api_apikey', 'auth_mo_api'),$apikey));

	$settings->add(new admin_setting_description('auth_mo_api/Authn_parameter',
            new lang_string('mo_api_authn_para', 'auth_mo_api'),
                 '{ "api_key": "'.$apikey.'" , "username" : "##username##","password" : "##password##" }'));


	//Attributes

	$settings->add(new admin_setting_heading('auth_mo_api/user_attributes',
            new lang_string('mo_api_attributes', 'auth_mo_api'), ''));

	$settings->add(new admin_setting_configtext('auth_mo_api/username',
            get_string('mo_api_username', 'auth_mo_api'),
            get_string('mo_api_username_desc', 'auth_mo_api'),'username', PARAM_RAW_TRIMMED));

	$settings->add(new admin_setting_configtext('auth_mo_api/fname',
            get_string('mo_api_fname', 'auth_mo_api'),
            get_string('mo_api_fname_desc', 'auth_mo_api'),'fname', PARAM_RAW_TRIMMED));

	$settings->add(new admin_setting_configtext('auth_mo_api/lname',
            get_string('mo_api_lname', 'auth_mo_api'),
            get_string('mo_api_lname_desc', 'auth_mo_api'),'lname', PARAM_RAW_TRIMMED));

	$settings->add(new admin_setting_configtext('auth_mo_api/email',
            get_string('mo_api_email', 'auth_mo_api'),
            get_string('mo_api_email_desc', 'auth_mo_api'),'email@gmail.com', PARAM_RAW_TRIMMED));

	$settings->add(new admin_setting_configtext('auth_mo_api/fullname',
            get_string('mo_api_fullname', 'auth_mo_api'),
            get_string('mo_api_fullname_desc', 'auth_mo_api'),'fullname', PARAM_RAW_TRIMMED));

}