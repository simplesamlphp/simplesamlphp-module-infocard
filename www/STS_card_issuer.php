<?php

/**
 * AUTHOR: Samuel Muñoz Hidalgo
 * EMAIL: samuel.mh@gmail.com
 * LAST REVISION: 24-APR-09
 * DESCRIPTION:
 *        Will send cards to other applications via web.
 *        Symmetric cryptography and IP filtering are available.
 */


/**
 * DESCRIPTION: used to encode the data attribute sent GET method
 * TAKEN FROM:  http://es2.php.net/manual/es/function.base64-encode.php#63543
 *
 * @param string $string
 * @return string
 */
function urlsafe_b64encode($string)
{
    $data = base64_encode($string);
    $data = str_replace(['+', '/', '='], ['-', '_', ''], $data);
    return $data;
}


/**
 * DESCRIPTION: used to decode the data attribute sent GET method
 * TAKEN FROM:  http://es2.php.net/manual/es/function.base64-encode.php#63543
 *
 * @param string $string
 * @return string
 */
function urlsafe_b64decode($string)
{
    $data = str_replace(['-', '_'], ['+', '/'], $string);
    $mod4 = strlen($data) % 4;
    if ($mod4) {
        $data .= substr('====', $mod4);
    }
    return base64_decode($data);
}


/**
 * CASE 1 AND 2
 * -Has Organization
 * -And chains to a trusted root CA
 * -NOTE: Based on V1.0, written for compatibility with DigitalMe PPID calculation
 *
 * @param array $certs
 * @return string
 */
function calculate_RP_PPID_Seed_2_2007($certs)
{
    $check_cert = openssl_x509_read(file_get_contents($certs[0]));
    $array = openssl_x509_parse($check_cert);
    openssl_x509_free($check_cert);
    $OrgIdString = '|O="' . $array['subject']['O'] . '"|L="' . $array['subject']['L']
        . '"|S="' . $array['subject']['ST'] . '"|C="' . $array['subject']['C'] . '"|';
    $numcerts = sizeof($certs);
    for ($i = 1; $i < $numcerts; $i++) {
        $check_cert = openssl_x509_read(file_get_contents($certs[$i]));
        $array = openssl_x509_parse($check_cert);
        openssl_x509_free($check_cert);
        $tmpstring = '|ChainElement="CN=' . $array['subject']['CN'] . ', OU=' . $array['subject']['OU'] . ', O='
        . $array['subject']['O'] . ', L=' . $array['subject']['L'] . ', S=' . $array['subject']['ST']
        . ', C=' . $array['subject']['C'] . '"';
        $OrgIdString = $tmpstring . $OrgIdString;
    }
    $OrgIdBytes = iconv("UTF-8", "UTF-16LE", $OrgIdString);
    $RPPPIDSeed = hash('sha256', $OrgIdBytes, true);
    return $RPPPIDSeed;
}


/**
 * DESCRIPTION: Calculate the PPID for a card
 * INPUT: card ID, and RP certificates
 * OUTPUT: PPID asociated to a Relying Party
 *
 * @param string $cardid
 * @param array $rp_cert
 * @return string
 */
function calculate_PPID($cardid, $rp_cert)
{
    $CardIdBytes = iconv("ISO-8859-1", "UTF-16LE", $cardid);
    $CanonicalCardId = hash('sha256', $CardIdBytes, true);
    $RPPPIDSeed = calculate_RP_PPID_Seed_2_2007($rp_cert);
    return hash('sha256', $RPPPIDSeed . $CanonicalCardId, true);
}


/**
 * INPUT: VOID
 * OUPUT: String with the invoked URL
 *
 * @return string
 */
function curPageURL()
{
    $pageURL = 'http';
    if ($_SERVER["HTTPS"] == "on") {
        $pageURL .= "s";
    }
    $pageURL .= "://";
    if ($_SERVER["SERVER_PORT"] != "80") {
        $pageURL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
    } else {
        $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
    }
    return $pageURL;
}




//TAD

/**
 * INPUT: String (attribute length + attribute not beginning with a number) n times , number of attributes
 * OUPUT: Array with attributes in order
 *
 * @param string $parsing_string
 * @param int $num_attrs
 * @return array|null
 */
function parse_attributes($parsing_string, $num_attrs)
{
    $output = [];
    for ($i = 0; $i < $num_attrs; $i++) {
        if (preg_match('/^[\d]*/', $parsing_string, $res)) {
            if (!($output[$i] = substr($parsing_string, strlen($res[0]), intval($res[0])))) {
                return null;
            }
            $parsing_string = substr($parsing_string, strlen($res[0]) + strlen($output[$i]));
        } else {
            return null;
        }
    }
    return $output;
}


/**
 * Enable downloading an specific card, store Radius request
 * INPUT: username, cardid, and radius request time
 * OUTPUT; uuid of the stored request
 *
 * @param string $username
 * @param string $cardid
 * @return false|string
 */
function enable_download($username, $cardid)
{
    //almacenar existencia
    
    //Add Timestamp to response
    $time = 'x' . time(); //Cannot start with a number
    
    $uuid = uniqid();
    $handle = fopen(SimpleSAML\Utils\System::getTempDir() . DIRECTORY_SEPARATOR . $uuid, 'w');
    if ($handle) {
        fwrite($handle, strlen($username) . $username . strlen($cardid) . $cardid . strlen($time) . $time);
        fclose($handle);
        return $uuid;
    } else {
        return false;
    }
}


/**
 * Disable downloading an specific card, should be called when ending a request = Infocard is Issued
 *
 * @param string $uuid
 * @return void
 */
function disable_download($uuid)
{
    unlink(SimpleSAML\Utils\System::getTempDir() . DIRECTORY_SEPARATOR . $uuid);
}


/**
 * ¿Should I generate a card?
 *
 * @param string $uuid
 * @param int $delivery_time
 * @return false|array
 */
function is_card_enabled($uuid, $delivery_time)
{
    $now = time();
    $filename = SimpleSAML\Utils\System::getTempDir() . DIRECTORY_SEPARATOR . $uuid;
    
    //File check
    if (!file_exists($filename)) {
        return false; //File doesn't exist
    }
    
    //Time check
    $handle = fopen($filename, 'r');
    if ($handle) {
        $data = fread($handle, filesize($filename));
        fclose($handle);
        
        $parsed_data = parse_attributes($data, 3);
        if (is_null($parsed_data)) {
            return false;
        }
        $parsed_data[2] = substr($parsed_data[2], 1); //Extracting numeric value
        
        $time = $parsed_data[2];
        $endtime = $time + $delivery_time;
        if (($now <= $time) || ($now > $endtime)) {
            return false; //Incorrect time
        }
        return $parsed_data;
    } else {
        return false; //Could not read the file
    }
}


/**
 * Check if the user is in the connected table
 * Update the row with the created Infocard card_ID
 *
 * @param string $username
 * @param array $DB_params
 * @return bool
 */
function DB_update_connected_user($username, $DB_params)
{
    $card_id = SimpleSAML\Module\InfoCard\UserFunctions::generate_card_ID($username);
    $dbconn = pg_connect('host=' . $DB_params['DB_host'] . '  port=' . $DB_params['DB_port'] . '  dbname='
        . $DB_params['DB_dbname'] . ' user=' . $DB_params['DB_user'] . '  password=' . $DB_params['DB_password']);
    $result = pg_fetch_all(pg_query_params($dbconn, 'SELECT * FROM connected_users WHERE name = $1', ["username"]));
    if ($result[0]) {
        pg_update($dbconn, 'connected_users', ['card_id' => $card_id], ['name' => $username]);
        return true;
    } else {
        return false;
    }
}



$config = \SimpleSAML\Configuration::getInstance();
$autoconfig = $config->getConfig('config-login-infocard.php');
$configuredIP = $autoconfig->getValue('configuredIP');


//RADIUS Request - Send One Time URL
if (
    (strcmp($_GET['ident'], 'RADIUS') == 0)
    && (($configuredIP == null)
    || ($_SERVER['REMOTE_ADDR'] == $configuredIP))
) {
    // Load the configuration
    $key = $autoconfig->getValue('symmetric_key');
    $internalkey = hash('sha256', $autoconfig->getValue('internal_key'));

    $encrequest = urlsafe_b64decode($_GET['data']);
    if (!$encrequest) {
        throw new \SimpleSAML\Error\NotFound('The URL wasn\'t found in the module.');
    }

    // Encryption
    $iv = '';
    if ($key !== null) {
        $iv = urlsafe_b64decode($_GET['iv']);
        if (!$iv) {
            throw new \SimpleSAML\Error\NotFound('The URL wasn\'t found in the module.');
        }
        $enckey = hash('sha256', $key);
        $request = mcrypt_decrypt(\MCRYPT_RIJNDAEL_128, pack("H*", $enckey), $encrequest, \MCRYPT_MODE_CBC, $iv);
    } else {
        $request = $encrequest;
    }

    //Parse Attributes (username lenght + username + cardid length + cardid)
    $parsed_request = parse_attributes($request, 2);

    //Enable card for downloading (username+cardid+time)
    $response = enable_download($parsed_request[0], $parsed_request[1]);
    if ($response === false) {
        throw new \SimpleSAML\Error\NotFound('FUNCTION enable_download, error accessing directory');
    }
    
    // Encrypt response for myself
    $response = mcrypt_encrypt(\MCRYPT_RIJNDAEL_128, pack("H*", $internalkey), $response, \MCRYPT_MODE_CBC, $iv);
    $response = preg_replace(
        '/\?.*/',
        '',
        curPageURL()
    );
    $response .= '?data=' . urlsafe_b64encode($response) . '&iv=' . urlsafe_b64encode($iv);
    

    // Encrypt response for RADIUS
    if ($key != null) {
        $encresponse = mcrypt_encrypt(\MCRYPT_RIJNDAEL_128, pack("H*", $enckey), $response, \MCRYPT_MODE_CBC, $iv);
    } else {
        $encresponse = $response;
    }
    
    // Send URL
    print base64_encode($encresponse);
} else {  //Client Resquest- Send InfoCard
    //Get Attributes
    $encrequest = urlsafe_b64decode($_GET['data']);
    $iv = urlsafe_b64decode($_GET['iv']);
    if ((!$encrequest) || (!$iv)) {
        throw new \SimpleSAML\Error\NotFound('The URL wasn\'t found in the module.');
    }

    // Load the configuration
    $internalkey = hash('sha256', $autoconfig->getValue('internal_key'));
    $certificates = $autoconfig->getArray('certificates', []);
    $ICconfig = [];
    $ICconfig['InfoCard'] = $autoconfig->getValue('InfoCard');
    //SimpleSAML\Module\InfoCard\Utils::getIssuer($sts_crt);
    $ICconfig['InfoCard']['issuer'] = $autoconfig->getValue('tokenserviceurl');
    $ICconfig['tokenserviceurl'] = $autoconfig->getValue('tokenserviceurl');
    $ICconfig['mexurl'] = $autoconfig->getValue('mexurl');
    $ICconfig['sts_key'] = $autoconfig->getValue('sts_key');
    $ICconfig['certificates'] = $autoconfig->getValue('certificates');
    $ICconfig['UserCredential'] = $autoconfig->getValue('UserCredential');
    $IC_lifetime_delivery = $autoconfig->getValue('IC_lifetime_delivery');
    $DB_params = $autoconfig->getValue('DB_params');

    // Encryption
    $request = mcrypt_decrypt(\MCRYPT_RIJNDAEL_128, pack("H*", $internalkey), $encrequest, \MCRYPT_MODE_CBC, $iv);
    
    $parsed_request = is_card_enabled($request, $IC_lifetime_delivery);
    if (($parsed_request !== false) && DB_update_connected_user($parsed_request[0], $DB_params)) {
        // Calculate PPID
        $ppid = base64_encode(calculate_PPID($parsed_request[1], $certificates));
    
        // Create InfoCard
        $ICdata = \SimpleSAML\Module\InfoCard\UserFunctions::fillICdata(
            $parsed_request[0],
            $ICconfig['UserCredential'],
            $ppid
        );
        $IC = \SimpleSAML\Module\InfoCard\STS::createCard($ICdata, $ICconfig);
        
        disable_download($request);
        
        //Send Infocard
        print ($IC);
    } else {
        throw new \SimpleSAML\Error\NotFound('The URL wasn\'t found in the module.');
    }
}
