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
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     auth_mo_api
 */

defined('MOODLE_INTERNAL') || die;

global $CFG;
require_once('functions.php');
require_once($CFG->libdir.'/authlib.php');


/**
 * This class contains authentication plugin method.
 *
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright  2020 miniOrange
 * @package    auth_mo_api
 */
class auth_plugin_mo_api extends auth_plugin_base {
    /**
     * Checking the value coming into this method is valid and empty.
     *
     * @param string $value
     * @return bool
     */
    public function mo_api_check_empty_or_null($value ) {
        if ( ! isset( $value ) || empty( $value ) ) {
            return true;
        }
        return false;
    }

    /**
     * auth_plugin_mo_api constructor.
     */
    public function __construct() {
        $this->authtype = 'mo_api';
        $this->roleauth = 'mo_api';
        $this->config = get_config('auth/mo_api');
    }

    /**
     * Checking curl installed or not. Return 1 if if present otherwise 0.
     * @return int
     */
    public function mo_api_is_curl_installed() {
        if (in_array  ('curl', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Checking openssl installed or not. Return 1 if if present otherwise 0.
     * @return int
     */
    public function mo_api_is_openssl_installed() {
        if (in_array  ('openssl', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Checking mcrypt installed or not. Return 1 if present otherwise 0.
     * @return int
     */
    public function mo_api_is_mcrypt_installed() {
        if (in_array  ('mcrypt', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * User login return boolean value after checking username and password combination.
     *
     * @param string $username username
     * @param string $password password
     * @return mixed array with no magic quotes or false on error
     */
    public function user_login($username, $password) {
        global $SESSION;
        if (isset($SESSION->mo_api_attributes)) {
            return true;
        }
        return false;
    }

    // Internal plugins use password hashes from Moodle user table for authentication.
    /**
     * Returns true if this authentication plugin is internal.
     * @return false
     */
    public function is_internal() {
        return false;
    }
    // This function automatically returns the opposite boolean of what is_internal() returns.
    // Returning true means MD5 password hashes will be stored in the user table.
    // Returning false means flag 'not_cached' will be stored there instead.
    /**
     * Indicates if password hashes should be stored in local moodle database.
     * @return bool
     */
    public function prevent_local_passwords() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change users' password.
     *
     * @return false
     */
    public function can_change_password() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can edit the users' profile.
     *
     * @return bool
     */
    public function can_edit_profile() {
        return true;
    }

}

/**
 * Get Attributes.
 *
 * @param string $value
 */
function attribute_getter($value) {
    $config = get_config('auth/mo_api');
    if ($config->username_api != "") {
        echo ',"'.$config->username_api.'":"'.$value->username.'"';
    }
    if ($config->first_name != "") {
        echo ',"'.$config->first_name.'":"'.$value->firstname.'"';
    }
    if ($config->last_name != "") {
        echo ',"'.$config->last_name.'":"'.$value->lastname.'"';
    }
    if ($config->email_att != "") {
        echo ',"'.$config->email_att.'":"'.$value->email.'"';
    }
    if ($config->full_name_attr != "") {
        echo ',"'.$config->full_name_attr.'":"'.$value->firstname, $value->lastname.'"';
    }
    echo '}';
}
