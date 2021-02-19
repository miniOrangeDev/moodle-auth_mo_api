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
 * This library is miniOrange Authentication Service.
 *
 * Contains important method for customer registration.
 *
 * @copyright   2020  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     auth_mo_api
 */
 defined('MOODLE_INTERNAL') || die();
/**
 * Auth external functions
 *
 * @package    auth_mo_api
 * @category   registration
 * @copyright  2020 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class customer_saml_api {
    public $email;
    /** @var $email contains email of admin.*/
    public $phone;
    /** @var $phone contains phone number of admin.*/
    /*
     * * Initial values are hardcoded to support the miniOrange framework to generate OTP for email.
     * * We need the default value for creating the first time,
     * * As we don't have the Default keys available before registering the user to our server.
     * * This default values are only required for sending an One Time Passcode at the user provided email address.
     */
    private $defaultcustomerkey = '16555';
    /** @var $defaultcustomerkey contains default customer key of admin.*/
    private $defaultapikey = 'fFd2XcvTGDemZvbw1bcUesNJWEqKbbUq';
    /** @var $defaultapikey contains default api key of admin.*/

    public function create_customer() {
        global $CFG, $USER;

        $config = get_config('auth/mo_api');
        $url = $config->hostname.'/moas/rest/customer/add';
        $ch = curl_init ( $url );
        $this->email = $config->adminemail;
        $password = $config->password;
        if (!isset($config->regfirstname)) {
            $config->regfirstname = $USER->firstname;
        }
        if (!isset($config->reglastname)) {
            $config->reglastname = $USER->lastname;
        }
        if (!isset($config->company)) {
            $config->company = $CFG->wwwroot;
        }
        if (!isset($config->phone)) {
            $config->phone = '';
        }
        $regfirstname = $config->regfirstname;
        $reglastname = $config->reglastname;
        $company = $config->company;
        $this->phone = $config->phone;
        $fields = array (
                'companyName' => $company,
                'areaOfInterest' => 'Moodle API Authentication Plugin',
                'firstname' => $regfirstname,
                'lastname' => $reglastname,
                'email' => $this->email,
                'phone' => $this->phone,
                'password' => $password
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF - 8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function get_customer_key() {
        $config = get_config('auth/mo_api');
        $url = $config->hostname.'/moas/rest/customer/key';
        $ch = curl_init ( $url );
        $email = $config->adminemail;
        $password = $config->password;
        $fields = array (
                'email' => $email,
                'password' => $password
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF - 8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function check_customer() {
        $config = get_config('auth/mo_api');
        $url = $config->hostname.'/moas/rest/customer/check-if-exists';
        $ch = curl_init ( $url );
        $email = $config->adminemail;
        $fields = array (
                'email' => $email
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF - 8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );

        return $content;
    }
    public function send_otp_token($email, $phone, $sendtoemail = true, $sendtophone = false) {
        $config = get_config('auth/mo_api');
        $url = $config->hostname.'/moas/api/auth/challenge';
        $ch = curl_init ( $url );
        $customerkey = $this->defaultcustomerkey;
        $apikey = $this->defaultapikey;
        // Current time in milliseconds since midnight, January 1, 1970 UTC.
        $currenttimeinmillis = round ( microtime ( true ) * 1000 );
        // Creating the Hash using SHA-512 algorithm.
        $stringtohash = $customerkey . number_format ( $currenttimeinmillis, 0, '', '' ) . $apikey;
        $hashvalue = hash ( 'sha512', $stringtohash );
        $customerkeyheader = 'Customer-Key: ' . $customerkey;
        $timestampheader = 'Timestamp: ' . number_format ( $currenttimeinmillis, 0, '', '' );
        $authorizationheader = 'Authorization: ' . $hashvalue;
        if ($sendtoemail) {
            $fields = array (
                    'customerKey' => $customerkey,
                    'email' => $email,
                    'authType' => 'EMAIL',
                    'transactionName' => 'Moodle API Authentication Plugin'
            );
        } else {
            $fields = array (
                    'customerKey' => $customerkey,
                    'phone' => $phone,
                    'authType' => 'SMS',
                    'transactionName' => 'Moodle API Authentication Plugin'
            );
        }
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                $customerkeyheader,
                $timestampheader,
                $authorizationheader
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function validate_otp_token($transactionide, $otptoken) {
        $config = get_config('auth/mo_api');
        $url = $config->hostname.'/moas/api/auth/validate';
        $ch = curl_init ( $url );
        $customerkey = $this->defaultcustomerkey;
        $apikey = $this->defaultapikey;
        $username = $config->adminemail;
        // Current time in milliseconds since midnight, January 1, 1970 UTC.
        $currenttimeinmillis = round ( microtime ( true ) * 1000 );
        // Creating the Hash using SHA-512 algorithm.
        $stringtohash = $customerkey . number_format ( $currenttimeinmillis, 0, '', '' ) . $apikey;
        $hashvalue = hash ( 'sha512', $stringtohash );
        $customerkeyheader = 'Customer-Key: ' . $customerkey;
        $timestampheader = 'Timestamp: ' . number_format ( $currenttimeinmillis, 0, '', '' );
        $authorizationheader = 'Authorization: ' . $hashvalue;
        $fields = '';
        // Check for otp over sms/email.
        $fields = array (
                'txId' => $transactionide,
                'token' => $otptoken
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                $customerkeyheader,
                $timestampheader,
                $authorizationheader
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function submit_contact_us($email, $phone, $query) {
        $config = get_config('auth/mo_api');
        $query = '[Moodle API Authentication Free Plugin] ' . $query;
        if (!isset($config->regfirstname)) {
            $config->regfirstname = '';
        }
        if (!isset($config->reglastname)) {
            $config->reglastname = '';
        }
        if (!isset($config->company)) {
            $config->company = $_SERVER ['SERVER_NAME'];
        }
        $regfirstname = $config->regfirstname;
        $reglastname = $config->reglastname;
        $company = $config->company;
        $fields = array (
                'firstName' => $config->regfirstname,
                'lastName' => $config->reglastname,
                'company' => $_SERVER ['SERVER_NAME'],
                'email' => $email,
                'ccEmail'=>'samlsupport@xecurify.com',
                'phone' => $phone,
                'query' => $query
        );
        $fieldstring = json_encode ( $fields );
        $url = $config->hostname.'/moas/rest/customer/contact-us';
        $ch = curl_init ( $url );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF-8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );

        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            return false;
        }
        curl_close ( $ch );
        return true;
    }
    
    public function mo_api_forgot_password($email) {
        $config = get_config('auth/mo_api');
        $url = $config->hostname.'/moas/rest/customer/password-reset';
        $ch = curl_init ( $url );
        // The customer Key provided to you.
        $customerkey = $config->admincustomerkey;
        // The customer API Key provided to you.
        $apikey = $config->adminapikey;
        // Current time in milliseconds since midnight, January 1, 1970 UTC.
        $currenttimeinmillis = round ( microtime ( true ) * 1000 );
        // Creating the Hash using SHA-512 algorithm.
        $stringtohash = $customerkey . number_format ( $currenttimeinmillis, 0, '', '' ) . $apikey;
        $hashvalue = hash ( 'sha512', $stringtohash );
        $customerkeyheader = 'Customer-Key: ' . $customerkey;
        $timestampheader = 'Timestamp: ' . number_format ( $currenttimeinmillis, 0, '', '' );
        $authorizationheader = 'Authorization: ' . $hashvalue;
        $fields = '';
        // Check for otp over sms/email.
        $fields = array (
                'email' => $email
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                $customerkeyheader,
                $timestampheader,
                $authorizationheader
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        curl_setopt ( $ch, CURLOPT_CONNECTTIMEOUT, 5 );
        curl_setopt ( $ch, CURLOPT_TIMEOUT, 20 );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }

    function check_internet_connection()
    {
        return (bool) @fsockopen('login.xecurify.com', 443, $iErrno, $sErrStr, 5);
    }
}