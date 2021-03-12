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
$config = get_config('auth/mo_api');

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
     * auth_plugin_mo_api constructor.
     */
    public function __construct() {
        $this->config = get_config('auth/mo_api');
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
    $config = get_config('auth_mo_api');

    if (!empty($config->username)) {
        echo ',"'.$config->username.'":"'.$value->username.'"';
    }
    if (!empty($config->fname)) {
        echo ',"'.$config->fname.'":"'.$value->firstname.'"';
    }
    if (!empty($config->lname)) {
        echo ',"'.$config->lname.'":"'.$value->lastname.'"';
    }
    if (!empty($config->email)) {
        echo ',"'.$config->email.'":"'.$value->email.'"';
    }
    if (!empty($config->fullname)) {
        echo ',"'.$config->fullname.'":"'.$value->firstname, $value->lastname.'"';
    }
    echo '}';
}
