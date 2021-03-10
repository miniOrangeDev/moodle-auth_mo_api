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

defined('MOODLE_INTERNAL') || die();
$config = get_config('auth/mo_api');

/**
 * Generating time stamp.
 *
 * @param null $instant
 * @return false|string
 */
function generate_timestamp_api($instant = null) {
    if ($instant === null) {
        $instant = time();
    }
    return gmdate('Y-m-d\TH:i:s\Z', $instant);
}

/**
 * Generate random id.
 *
 * @return string
 */
function generate_id_api() {
    return '_' .string_to_hex_api(generate_random_bytes(21));
}

/**
 * Value conversion method for string_to_hex.
 *
 * @param string $bytes
 * @return string
 */
function string_to_hex_api($bytes) {
    $ret = '';
    for ($i = 0; $i < strlen($bytes); $i++) {
        $ret .= sprintf('%02x', ord($bytes[$i]));
    }
    return $ret;
}

/**
 * Generate_random_bytes produce random bytes of given length.
 *
 * @param int $length
 * @param bool $fallback
 * @return false|string
 */
function generate_random_bytes_api($length, $fallback = true) {
    return openssl_random_pseudo_bytes($length);
}


