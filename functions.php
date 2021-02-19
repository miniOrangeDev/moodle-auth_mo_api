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
 *
 * @copyright   2020  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     auth_mo_api
 */
defined('MOODLE_INTERNAL') || die();
$config = get_config('auth/mo_api');

// Get_random_password is method which generates random password for every non-manual user.
function get_random_password_api() {
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
    $pass = array();
    $alphalength = strlen($alphabet) - 1;
    for ($i = 0; $i < 30; $i++) {
        $n = rand(0, $alphalength);
        $pass[] = $alphabet[$n];
    }
    return implode($pass);
}
// Timestamp for instant issuer.
function generate_timestamp_api($instant = null) {
    if ($instant === null) {
        $instant = time();
    }
    return gmdate('Y-m-d\TH:i:s\Z', $instant);
}
function generate_id_api() {
    return '_' .string_to_hex_api(generate_random_bytes(21));
}
// Value conversion method for string_to_hex.
function string_to_hex_api($bytes) {
    $ret = '';
    for ($i = 0; $i < strlen($bytes); $i++) {
        $ret .= sprintf('%02x', ord($bytes[$i]));
    }
    return $ret;
}
// Generate_random_bytes produce random bytes of given length.
function generate_random_bytes_api($length, $fallback = true) {
    return openssl_random_pseudo_bytes($length);
}


