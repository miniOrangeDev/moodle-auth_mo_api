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
 * @category    Authentication
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
 * @package    auth_mo_api
 * @category   Authentication
 * @copyright  2020 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

class auth_plugin_mo_api extends auth_plugin_base {
    // Checking the value coming into this method is valid and empty.
    /**
     * @param $value
     * @return bool
     */
    public function mo_api_check_empty_or_null($value ) {
        if ( ! isset( $value ) || empty( $value ) ) {
            return true;
        }
        return false;
    }
    // Constructor which has authtype, roleauth, and config variable initialized.

    /**
     * auth_plugin_mo_api constructor.
     */
    public function __construct() {
        $this->authtype = 'mo_api';
        $this->roleauth = 'mo_api';
        $this->config = get_config('auth/mo_api');
    }
    // Checking curl installed or not. Return 1 if if present otherwise 0.

    /**
     * @return int
     */
    public function mo_api_is_curl_installed() {
        if (in_array  ('curl', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // Checking openssl installed or not. Return 1 if if present otherwise 0.

    /**
     * @return int
     */
    public function mo_api_is_openssl_installed() {
        if (in_array  ('openssl', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // Checking mcrypt installed or not. Return 1 if if present otherwise 0.

    /**
     * @return int
     */
    public function mo_api_is_mcrypt_installed() {
        if (in_array  ('mcrypt', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // User login return boolean value after checking username and password combination.

    /**
     * @param $username
     * @param $password
     * @return bool
     */
    public function user_login($username, $password) {
        global $SESSION;
        if (isset($SESSION->mo_api_attributes)) {
            return true;
        }
        return false;
    }
    // Here we are assigning  role to user which is selected in role mapping.

    /**
     * @return string
     */
    public function obtain_roles() {
        global $SESSION;
        $roles = 'Manager';
        if (!empty($this->config->defaultrolemap) && isset($this->config->defaultrolemap)) {
            $roles = $this->config->defaultrolemap;
        }
        return $roles;
    }


    // Sync roles assigne the role for new user if role mapping done in default role.

    /**
     * @param $user
     */
    public function sync_roles($user) {
        global $CFG, $DB;
        $defaultrole = $this->obtain_roles();
        if ('siteadmin' == $defaultrole) {
            $siteadmins = explode(',', $CFG->siteadmins);
            if (!in_array($user->id, $siteadmins)) {
                $siteadmins[] = $user->id;
                $newadmins = implode(',', $siteadmins);
                set_config('siteadmins', $newadmins);
            }
        }

        // Consider $roles as the groups returned from IdP.

        $checkrole = false;
        if ($checkrole == false) {
            $syscontext = context_system::instance();
            $assignedrole = $DB->get_record('role', array('shortname' => $defaultrole), '*', MUST_EXIST);
            role_assign($assignedrole->id, $user->id, $syscontext);
        }
    }
    // Returns true if this authentication plugin is internal.
    // Internal plugins use password hashes from Moodle user table for authentication.
    /**
     * @return false
     */
    public function is_internal() {
        return false;
    }
    // Indicates if password hashes should be stored in local moodle database.
    // This function automatically returns the opposite boolean of what is_internal() returns.
    // Returning true means MD5 password hashes will be stored in the user table.
    // Returning false means flag 'not_cached' will be stored there instead.
    /**
     * @return bool
     */
    public function prevent_local_passwords() {
        return true;
    }
    // Returns true if this authentication plugin can change users' password.

    /**
     * @return false
     */
    public function can_change_password() {
        return false;
    }
    // Returns true if this authentication plugin can edit the users' profile.

    /**
     * @return bool
     */
    public function can_edit_profile() {
        return true;
    }
    // Hook for overriding behaviour of login page.

    /**
     *
     */
    public function loginpage_hook() {
        global $CFG;
        $config = get_config('auth/mo_api');
        $CFG->nolastloggedin = true;

        if (isset($config->identityname)) {
            ?>
            <script src='../auth/mo_api/includes/js/jquery.min.js'></script>
            <script>$(document).ready(function(){
                $('<a class = "btn btn-primary btn-block m-t-1" style="margin-left:auto; 
                    "href="<?php echo $CFG->wwwroot.'/auth/mo_api/index.php';
                ?>">Login with <?php echo($this->config->identityname); ?> </a>').insertAfter('#loginbtn')
            });</script>
            <?php
        }
    }
    // Hook for overriding behaviour of logout page.

    /**
     *
     */
    public function logoutpage_hook() {
        global $SESSION, $CFG;
        $logouturl = $CFG->wwwroot.'/login/index.php?saml_sso=false';
        require_logout();
        set_moodle_cookie('nobody');
        redirect($logouturl);
    }

    // Validate form data.

    /**
     * @param $form
     * @param $err
     */
    public function validate_form($form, &$err) {
        // Registeration of plugin also submitting a form which is validating here.
        if (required_param('option', PARAM_RAW) == 'mo_api_register_customer') {
            $loginlink = "auth_config.php?auth=mo_api&tab=login";
            if ( $this->mo_api_check_empty_or_null( required_param('email', PARAM_RAW) ) ||
                $this->mo_api_check_empty_or_null( required_param('password', PARAM_RAW) ) ||
                $this->mo_api_check_empty_or_null( required_param('confirmpassword', PARAM_RAW) ) ) {
                $err['requiredfield'] = 'Please enter the required fields.';
                redirect($loginlink, 'Please enter the required fields.', null, \core\output\notification::NOTIFY_ERROR);
            } else if ( strlen( required_param('password', PARAM_RAW) ) < 6 ||
                strlen( required_param('confirmpassword', PARAM_RAW) ) < 6) {
                $err['passwordlengtherr'] = 'Choose a password with minimum length 6.';
                redirect($loginlink, 'Choose a password with minimum length 6.', null, \core\output\notification::NOTIFY_ERROR);
            }
        }
        // Attribute /Role mapping data are validate here.
    }
}

/**
 * @param $value
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
