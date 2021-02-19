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

global $CFG;
require_once('functions.php');
require_once('customer.php');
require_once($CFG->libdir.'/authlib.php');


/**
 * This class contains authentication plugin method
 *
 * @package    auth_mo_api
 * @category   authentication
 * @copyright  2020 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later

 */

class auth_plugin_mo_api extends auth_plugin_base {
    // Checking the value coming into this method is valid and empty.
    public function mo_api_check_empty_or_null( $value ) {
        if ( ! isset( $value ) || empty( $value ) ) {
            return true;
        }
        return false;
    }
    // Constructor which has authtype, roleauth, and config variable initialized.
    public function __construct() {
        $this->authtype = 'mo_api';
        $this->roleauth = 'mo_api';
        $this->config = get_config('auth/mo_api');
    }
    // Checking curl installed or not. Return 1 if if present otherwise 0.
    public function mo_api_is_curl_installed() {
        if (in_array  ('curl', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // Checking openssl installed or not. Return 1 if if present otherwise 0.
    public function mo_api_is_openssl_installed() {
        if (in_array  ('openssl', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // Checking mcrypt installed or not. Return 1 if if present otherwise 0.
    public function mo_api_is_mcrypt_installed() {
        if (in_array  ('mcrypt', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // User login return boolean value after checking username and password combination.
    public function user_login($username, $password) {
        global $SESSION;
        if (isset($SESSION->mo_api_attributes)) {
            return true;
        }
        return false;
    }
    
 


    // Here we are assigning  role to user which is selected in role mapping.
    public function obtain_roles() {
        global $SESSION;
        $roles = 'Manager';
        if (!empty($this->config->defaultrolemap) && isset($this->config->defaultrolemap)) {
            $roles = $this->config->defaultrolemap;
        }
        return $roles;
    }


    // Sync roles assigne the role for new user if role mapping done in default role.
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

        //consider $roles as the groups returned from IdP

        $checkrole = false;


        if($checkrole == false){
            $syscontext = context_system::instance();
            $assignedrole = $DB->get_record('role', array('shortname' => $defaultrole), '*', MUST_EXIST);
            role_assign($assignedrole->id, $user->id, $syscontext);
        }
    }
    // Returns true if this authentication plugin is internal.
    // Internal plugins use password hashes from Moodle user table for authentication.
    public function is_internal() {
        return false;
    }
    // Indicates if password hashes should be stored in local moodle database.
    // This function automatically returns the opposite boolean of what is_internal() returns.
    // Returning true means MD5 password hashes will be stored in the user table.
    // Returning false means flag 'not_cached' will be stored there instead.
    public function prevent_local_passwords() {
        return true;
    }
    // Returns true if this authentication plugin can change users' password.
    public function can_change_password() {
        return false;
    }
    // Returns true if this authentication plugin can edit the users' profile.
    public function can_edit_profile() {
        return true;
    }
    // Hook for overriding behaviour of login page.
    public function loginpage_hook() {
        global $CFG;
        $config = get_config('auth/mo_api');
        $CFG->nolastloggedin = true;

        if(isset($config->identityname)){
            ?>
            <script src='../auth/mo_api/includes/js/jquery.min.js'></script>
            <script>$(document).ready(function(){
                $('<a class = "btn btn-primary btn-block m-t-1" style="margin-left:auto;"  href="<?php echo $CFG->wwwroot.'/auth/mo_api/index.php';
                ?>">Login with <?php echo($this->config->identityname); ?> </a>').insertAfter('#loginbtn')
            });</script>
            <?php
        }
    }
    // Hook for overriding behaviour of logout page.
    public function logoutpage_hook() {
        global $SESSION, $CFG;
        $logouturl = $CFG->wwwroot.'/login/index.php?saml_sso=false';
        require_logout();
        set_moodle_cookie('nobody');
        redirect($logouturl);
    }
    // Prints a form for configuring this authentication plugin.
    // It's called from admin/auth.php, and outputs a full page with a form for configuring this plugin.
    public function config_form($config, $err, $userfields) {
        include('config.html');
        // Including page for setting up the plugin data.
    }
    // Validate form data.
    public function validate_form($form, &$err) {
        // Registeration of plugin also submitting a form which is validating here.
        if (isset($_POST['option']) and $_POST[ 'option' ] == 'mo_api_register_customer') 
        {
            $loginlink = "auth_config.php?auth=mo_api&tab=login";
            if ( $this->mo_api_check_empty_or_null( $_POST['email'] ) ||
                $this->mo_api_check_empty_or_null( $_POST['password'] ) ||
                $this->mo_api_check_empty_or_null( $_POST['confirmpassword'] ) ) {
                $err['requiredfield'] = 'Please enter the required fields.';
                redirect($loginlink, 'Please enter the required fields.', null, \core\output\notification::NOTIFY_ERROR);
            } else if ( strlen( $_POST['password'] ) < 6 || strlen( $_POST['confirmpassword'] ) < 6) {
                $err['passwordlengtherr'] = 'Choose a password with minimum length 6.';
                redirect($loginlink, 'Choose a password with minimum length 6.', null, \core\output\notification::NOTIFY_ERROR);
            }
        }
 

        // Attribute /Role mapping data are validate here.
    }
    // Processes and stores configuration data for this authentication plugin.
    public function process_config($config) {
        global $CFG;
        // CFG contain base url for the moodle.
        $config = get_config('auth/mo_api');
        set_config('hostname', 'https://login.xecurify.com', 'auth/mo_api');
        // Set host url here for rgister and login purpose of plugin.
        $actuallink = $_SERVER['HTTP_REFERER'];
        /*if (isset($_POST['option']) and $_POST[ 'option' ] == 'mo_api_register_customer') {
            


        }  */      

        if (isset($_POST['option']) and $_POST[ 'option' ] == 'mo_api_register_customer') {
            if (!isset($_POST['email'])) {
                $config->adminemail = '';
            }
            if (!isset($_POST['password'])) {
                $config->password = '';
            }
            if (!isset($_POST['confirmpassword'])) {
                $config->confirmpassword = '';
            }
            if (!isset($config->transactionid)) {
                $config->transactionid = '';
            }
            if (!isset($config->registrationstatus)) {
                $config->registrationstatus = '';
            }
            set_config('adminemail', $_POST['email'], 'auth/mo_api');
            set_config('company', $CFG->wwwroot, 'auth/mo_api');
                
            if ( strcmp( $_POST['password'], $_POST['confirmpassword']) == 0 ) {
                set_config('password', $_POST['password'], 'auth/mo_api');
                $customer = new customer_saml_api();
                $content = json_decode($customer->check_customer(), true);
                if(!is_null($content))
                {
                    if ( strcasecmp( $content['status'], 'CUSTOMER_NOT_FOUND' ) == 0 ) 
                    {
                        $this->create_customer();
                    } 
                    else 
                    {
                        $licenselink = "auth_config.php?auth=mo_api&tab=license"; 
                        $this->get_current_customer();
                        redirect($licenselink, 'Account already exists!', null, \core\output\notification::NOTIFY_WARNING);
                    }
                }
            } 
            else 
            {
                set_config('verifycustomer', '', 'auth/mo_api');
                redirect($actuallink, 'Passwords do not match!', null, \core\output\notification::NOTIFY_ERROR);
            }
            redirect($actuallink);
            return true;
        }
        if (isset($_POST['option']) and $_POST['option'] == 'mo_api_validate_otp') {
            // Validation and sanitization.
            $otptoken = '';
            if ( $this->mo_api_check_empty_or_null( $_POST['otp_token'] ) ) {
                echo('registrationstatus-MO_OTP_VALIDATION_FAILURE');
                return;
            } else {
                $otptoken = $_POST['otp_token'];
            }
            $customer = new customer_saml_api();
            $content = json_decode($customer->validate_otp_token($config->transactionid, $otptoken ), true);
            if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                $this->create_customer();
            } else {
                // Invalid one time passcode. Please enter a valid otp.
                echo('registrationstatus-MO_OTP_VALIDATION_FAILURE');
            }
            redirect($actuallink);
            return true;
        }
        if ( isset( $_POST['option'] ) and $_POST['option'] == 'verifycustomer' ) {
            if (!isset($config->adminemail)) {
                $config->adminemail = '';
            }
            if (!isset($config->password)) {
                $config->password = '';
            }
            set_config('adminemail', trim($_POST['email']), 'auth/mo_api');
            set_config('password', trim($_POST['password']), 'auth/mo_api');
            $config = get_config('auth/mo_api');
            $customer = new customer_saml_api();
            $content = $customer->get_customer_key();
            $customerkey = json_decode( $content, true );
            if ( json_last_error() == JSON_ERROR_NONE ) {
                set_config( 'admincustomerkey', $customerkey['id'] , 'auth/mo_api');
                set_config( 'adminapikey', $customerkey['apiKey'], 'auth/mo_api' );
                set_config( 'customertoken', $customerkey['token'] , 'auth/mo_api');
                
                if(isset($config->samlxcertificate))
                    $certificate = $config->samlxcertificate;
                if (empty($certificate)) {
                    set_config( 'freeversion', 1 , 'auth/mo_api');
                }
                
                set_config('registrationstatus', 'Existing User', 'auth/mo_api');
                set_config('verifycustomer', '', 'auth/mo_api');
                $account_info = "auth_config.php?auth=mo_api&tab=account_info"; 
                redirect($account_info, 'Login success!', null, \core\output\notification::NOTIFY_SUCCESS);
            } else {
                // Invalid username or password. Please try again.
                // echo('Invalid Username or Password');
                redirect($actuallink, 'Invalid Username or Password!', null, \core\output\notification::NOTIFY_ERROR);
            }
            
            return true;
        } else if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_api_contact_us_query_option' ) {
            // Contact Us query.
            $email = $_POST['mo_api_contact_us_email'];
            $phone = $_POST['mo_api_contact_us_phone'];
            $query = $_POST['mo_api_contact_us_query'];
            $customer = new customer_saml_api();
            if ( $this->mo_api_check_empty_or_null( $email ) || $this->mo_api_check_empty_or_null( $query ) ) {
                redirect($actuallink);
            } else {
                $submited = $customer->submit_contact_us( $email, $phone, $query );
                if ( $submited == false ) {
                    echo('Error During Query Submit');exit;
                } else {
                    echo('Query Submitted By You...');
                    redirect($CFG->wwwroot.'/admin/auth_config.php?auth=mo_api&tab=config','Query submitted successfully! We will reach out to you soon.',null,\core\output\notification::NOTIFY_SUCCESS );
                    return true;
                }
            }
        } else if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_api_resend_otp_email') {
            $email = $config->adminemail;
            $customer = new customer_saml_api();
            $content = json_decode($customer->send_otp_token($email, ''), true);
            if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                    set_config('transactionid', $content['txId'], 'auth/mo_api');
                    set_config('registrationstatus', 'MO_OTP_DELIVERED_SUCCESS_EMAIL', 'auth/mo_api');
            } else {
                    set_config('registrationstatus', 'MO_OTP_DELIVERED_FAILURE_EMAIL', 'auth/mo_api');
            }
            redirect($actuallink);
            return true;
        } else if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_api_resend_otp_phone' ) {
            $phone = $config->phone;
            $customer = new customer_saml_api();
            $content = json_decode($customer->send_otp_token('', $phone, false, true), true);
            if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                    set_config('transactionid', $content['txId'], 'auth/mo_api');
                    set_config('registrationstatus', 'MO_OTP_DELIVERED_SUCCESS_PHONE', 'auth/mo_api');
            } else {
                    set_config('registrationstatus', 'MO_OTP_DELIVERED_FAILURE_PHONE', 'auth/mo_api');
            }
            redirect($actuallink);
            return true;
        }
        if (isset( $_POST['option'] ) and $_POST['option'] == 'mo_api_go_registration' ) 
        {
            unset_config('verifycustomer', 'auth/mo_api');
            $actuallink = 'auth_config.php?auth=mo_api&tab=login';
            redirect($actuallink);
            return true;
        }
        if (isset( $_POST['option'] ) and $_POST['option'] == 'mo_api_go_login' ) 
        {
            unset_config('adminapikey', 'auth/mo_api');
            unset_config('admincustomerkey', 'auth/mo_api');
            unset_config('customertoken', 'auth/mo_api');
            unset_config('password', 'auth/mo_api');

            set_config('verifycustomer','true', 'auth/mo_api');
            $actuallink = 'auth_config.php?auth=mo_api&tab=login';
            redirect($actuallink);
            return true;
        }
        if (isset( $_POST['option'] ) and $_POST['option'] == 'mo_api_go_back' ) 
        {
            unset_config('adminapikey', 'auth/mo_api');
            unset_config('admincustomerkey', 'auth/mo_api');
            unset_config('company', 'auth/mo_api');
            unset_config('customertoken', 'auth/mo_api');
            unset_config('license_key', 'auth/mo_api');
            unset_config('license_verified', 'auth/mo_api');
            unset_config('newregistration', 'auth/mo_api');
            unset_config('password', 'auth/mo_api');
            unset_config('phone', 'auth/mo_api');
            unset_config('regfirstname', 'auth/mo_api');
            unset_config('registrationstatus', 'auth/mo_api');
            unset_config('reglastname', 'auth/mo_api');
            unset_config('vl_check_t', 'auth/mo_api');

            set_config('verifycustomer','true', 'auth/mo_api');
            $actuallink = 'auth_config.php?auth=mo_api&tab=login';

            redirect($actuallink);
            return true;
        } else if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_api_register_with_phone_option' ) {
            $phone = $_POST['phone'];
            $phone = str_replace(' ', '', $phone);
            $phone = str_replace('-', '', $phone);
            set_config('phone', $phone, 'auth/mo_api');
            $customer = new customer_saml_api();
            $content = json_decode($customer->send_otp_token('', $phone, false, true), true);
            if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                set_config('transactionid', $content['txId'], 'auth/mo_api');
                set_config('registrationstatus', 'MO_OTP_DELIVERED_SUCCESS_PHONE', 'auth/mo_api');
            } else {
                set_config('registrationstatus', 'MO_OTP_DELIVERED_FAILURE_PHONE', 'auth/mo_api');
            }
            redirect($actuallink);
            return true;
        }
        if (isset( $_POST['option'] ) and $_POST[ 'option' ] == 'save') {

            if (!isset($config->identityname)) {
                $config->identityname = '';
            }
            if (!isset($config->loginurl)) {
                $config->loginurl = '';
            }
            if (!isset($config->samlissuer)) {
                $config->samlissuer = '';
            }
            if (!isset($config->samlxcertificate)) {
                $config->samlxcertificate = '';
            }
            $certificatex = trim($_POST['samlxcertificate']);
            $certificatex = $this->sanitize_certificate($_POST['samlxcertificate']);
            set_config('identityname', trim($_POST['identityname']), 'auth/mo_api');
            
            set_config('loginurl', trim($_POST['loginurl']), 'auth/mo_api');
            set_config('samlissuer', trim($_POST['samlissuer']), 'auth/mo_api');
            set_config('samlxcertificate', trim($certificatex), 'auth/mo_api');

            redirect($actuallink, 'Settings saved successfully!', null, \core\output\notification::NOTIFY_SUCCESS);
            return true;
        }
        if (isset($_POST['option']) and $_POST[ 'option' ] == 'mo_api_verify_license') 
        {
            $redirect_url = "auth_config.php?auth=mo_api&tab=config";
            redirect($redirect_url);
            return true;
        }
        if ( isset( $_POST['option'] ) and $_POST['option'] == 'general') {

            if (!isset($config->enableloginredirect)) {
                $config->enableloginredirect = '';
            }

            if(!isset($config->loginurl))
            {
                redirect($actuallink, 'Configure the plugin first! Go to the <b>Service Provider Setup</b> tab.', null, \core\output\notification::NOTIFY_ERROR);
            }

            if(array_key_exists('mo_api_enable_login_redirect',$_POST))
                set_config('enableloginredirect', trim($_POST['mo_api_enable_login_redirect']), 'auth/mo_api');
            else
                unset_config('enableloginredirect', 'auth/mo_api');
            
            redirect($actuallink);
            return true;
        }
        
       if (isset( $_POST['option'] ) and $_POST[ 'option' ] == 'generate')
        {
            $apikey = get_random_password_api();
            set_config('apikey', $apikey, 'auth/mo_api');
            redirect($actuallink,'New key generated successfully!', null, \core\output\notification::NOTIFY_SUCCESS);
        }
        //$apikey='Jg>P1yZQ>Swi+`c6Bfv--3V*=kI:##QPn<NgzH!I0C2,dlk^)@~%reWz|y6Q0C1';
       // set_config('apikey', $apikey, 'auth/mo_api');

        if (isset( $_POST['option'] ) and $_POST[ 'option' ] == 'Save')
        {
            if (!isset($config->first_name)) {
                $config->first_name = '';
            }
            if (!isset($config->last_name)) {
                $config->last_name = '';
            }
            if (!isset($config->email_att)) {
                $config->email_att = '';
            }
            if (!isset($config->full_name_attr)) {
                $config->full_name_attr = '';
            }
            if (!isset($config->username_api)) {
                $config->username_api = '';
            }
            set_config('username_api', $_POST['username_api'], 'auth/mo_api');            
            set_config('full_name_attr', $_POST['full_name_attr'], 'auth/mo_api');
            set_config('first_name', $_POST['first_name'], 'auth/mo_api');
            set_config('last_name',  $_POST['last_name'], 'auth/mo_api');
            set_config('email_att',  $_POST['email_att'], 'auth/mo_api');
            redirect($actuallink,'Changes successfully saved!', null, \core\output\notification::NOTIFY_SUCCESS);
    

        }
        return true;
    }
   
    public function create_customer() {
        global $CFG;
        $customer = new customer_saml();
        $customerkey = json_decode( $customer->create_customer(), true );
        if ( strcasecmp( $customerkey['status'], 'CUSTOMER_USERNAME_ALREADY_EXISTS') == 0 ) {
                    $this->get_current_customer();
        } else if ( strcasecmp( $customerkey['status'], 'SUCCESS' ) == 0 ) {
            set_config( 'admincustomerkey', trim($customerkey['id']), 'auth/mo_api' );
            set_config( 'adminapikey', $customerkey['apiKey'], 'auth/mo_api');
            set_config( 'customertoken', $customerkey['token'], 'auth/mo_api');
            set_config( 'freeversion', 1, 'auth/mo_api' );
            set_config('password', '', 'auth/mo_api');
            set_config('registrationstatus', '', 'auth/mo_api');
            set_config('verifycustomer', '', 'auth/mo_api');
            set_config('newregistration', '', 'auth/mo_api');
            redirect($CFG->wwwroot.'/admin/auth_config.php?auth=mo_api&tab=license');
        }
        set_config('password', '', 'auth/mo_api');
    }
    // Getting customer which is already created at host for login purpose.
    public function get_current_customer() {
        global $CFG;
        $customer = new customer_saml_api();
        $content = $customer->get_customer_key();
        $customerkey = json_decode( $content, true );
        if ( json_last_error() == JSON_ERROR_NONE ) {
            set_config( 'admincustomerkey', trim($customerkey['id']), 'auth/mo_api' );
            set_config( 'adminapikey', $customerkey['apiKey'] , 'auth/mo_api');
            set_config( 'customertoken', $customerkey['token'] , 'auth/mo_api');
            set_config('password', '', 'auth/mo_api');

            set_config('verifycustomer', '', 'auth/mo_api');
            set_config('newregistration', '', 'auth/mo_api');
        //    redirect($actuallink);
        } else {
            set_config('verifycustomer', 'true', 'auth/mo_api');
            set_config('newregistration', '', 'auth/mo_api');
        }
    }
    // The page show in test configuration page.
   /* public function test_settings() {
        global $CFG;
        echo ' <iframe style="width: 690px;height: 790px;" src="'
        .$CFG->wwwroot.'/auth/mo_api/index.php/?option=testConfig"></iframe>';
    }*/
}
function attribute_getter($value){
    $config = get_config('auth/mo_api');
    if($config->username_api !=""){
    echo ',"'.$config->username_api.'":"'.$value->username.'"';
    }
    if($config->first_name !=""){
    echo ',"'.$config->first_name.'":"'.$value->firstname.'"';
    }   
    if($config->last_name !=""){
    echo ',"'.$config->last_name.'":"'.$value->lastname.'"';
        }
    if($config->email_att !=""){
        echo ',"'.$config->email_att.'":"'.$value->email.'"';
    }
    if($config->full_name_attr !=""){
        echo ',"'.$config->full_name_attr.'":"'.$value->firstname,$value->lastname.'"';
    }
    
    echo '}';
}
