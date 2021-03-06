<?php

/**
 * AUTHOR: Samuel Muñoz Hidalgo
 * EMAIL: samuel.mh@gmail.com
 * LAST REVISION: 13-FEB-09
 * DESCRIPTION: Web interface for the token generator
 */


/**
 * Borrowed from xlmseclibs, TEMPORAL
 *
 * @param string $data
 * @param string $key
 * @return string
 */
function decryptMcrypt($data, $key)
{
    $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
    $iv_length = mcrypt_enc_get_iv_size($td);

    $iv = substr($data, 0, $iv_length);
    $data = substr($data, $iv_length);

    mcrypt_generic_init($td, $key, $iv);
    $decrypted_data = mdecrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    
    $dataLen = strlen($decrypted_data);
    $paddingLength = substr($decrypted_data, $dataLen - 1, 1);
    $decrypted_data = substr($decrypted_data, 0, $dataLen - ord($paddingLength));
    
    return $decrypted_data;
}


/**
 * Input: self issued saml token
 * Returns ppid coded in base 64
 *
 * @param string $samlToken
 * @return string|null
 */
function getppid($samlToken)
{
    $token = new DOMDocument();
    $token->loadXML($samlToken);
    $doc = $token->documentElement;
    return is_null($doc) ? '' : $doc->getElementsByTagname('AttributeValue')->item(0)->nodeValue;
}


/**
 * grab the important parts of the token request.  these are the username,
 * password, and cardid
 */
Header('Content-Type: application/soap+xml;charset=utf-8');

$config = \SimpleSAML\Configuration::getInstance();
\SimpleSAML\Logger::debug('Tokenservice');

$token = new DOMDocument();
/** @psalm-suppress UndefinedGlobalVariable */
$token->loadXML($HTTP_RAW_POST_DATA);
$doc = $token->documentElement;

$cardId = $doc->getElementsByTagname('CardId')->item(0)->nodeValue;

$authenticated = false;


$autoconfig = $config->getConfig('config-login-infocard.php');
$ICconfig['UserCredential'] = $autoconfig->getValue('UserCredential');
$debugDir = $autoconfig->getValue('debugDir');


\SimpleSAML\Logger::debug('USERCREDENTIAL: ' . $ICconfig['UserCredential']);
switch ($ICconfig['UserCredential']) {
    case "UsernamePasswordCredential":
        $username = $doc->getElementsByTagname('Username')->item(0)->nodeValue;
        $password = $doc->getElementsByTagname('Password')->item(0)->nodeValue;
        if (
            \SimpleSAML\Module\InfoCard\UserFunctions::validateUser(
                ['username' => $username, 'password' => $password],
                $ICconfig['UserCredential']
            )
        ) {
            $authenticated = true;
        }
        break;
    case "KerberosV5Credential":
        break;
    case "X509V3Credential":
        break;
    case "SelfIssuedCredential":
        //Obtener clave simétrica
        $encKey = base64_decode($doc->getElementsByTagname('CipherValue')->item(0)->nodeValue);
        $sts_key = $autoconfig->getValue('sts_key');
        $privkey = openssl_pkey_get_private(file_get_contents($sts_key));
        $key = null;
        openssl_private_decrypt($encKey, $key, $privkey, OPENSSL_PKCS1_OAEP_PADDING);
        openssl_free_key($privkey);
        
        //Recuperar información
        $encSamlToken = base64_decode($doc->getElementsByTagname('CipherValue')->item(1)->nodeValue);
        $samlToken = decryptMcrypt($encSamlToken, $key);
        SimpleSAML\Logger::debug('$samlToken' . $samlToken);
        $ppid = getppid($samlToken);
        SimpleSAML\Logger::debug('PPID: ' . $ppid);

        if (\SimpleSAML\Module\InfoCard\UserFunctions::validateUser(['PPID' => $ppid], $ICconfig['UserCredential'])) {
            $authenticated = true;
        }
        break;
    default:
        break;
}


$messageid = $doc->getElementsByTagname('MessageID')->item(0)->nodeValue;

if ($authenticated) {
    $ICconfig['InfoCard'] = $autoconfig->getValue('InfoCard');
    $ICconfig['issuer'] = $autoconfig->getValue('issuer');
    $ICconfig['sts_crt'] = $autoconfig->getValue('sts_crt');
    $ICconfig['sts_key'] = $autoconfig->getValue('sts_key');
    
    $requiredClaims = \SimpleSAML\Module\InfoCard\Utils::extractClaims(
        $ICconfig['InfoCard']['schema'],
        $doc->getElementsByTagname('ClaimType')
    );
    $claimValues = \SimpleSAML\Module\InfoCard\UserFunctions::fillClaims(
        $username,
        $ICconfig['InfoCard']['requiredClaims'],
        $ICconfig['InfoCard']['optionalClaims'],
        $requiredClaims
    );
    
    $response = \SimpleSAML\Module\InfoCard\STS::createToken($claimValues, $ICconfig, $messageid);
} else {
    $response = \SimpleSAML\Module\InfoCard\STS::errorMessage('Wrong Credentials', $messageid);
}


Header('Content-length: ' . strlen($response) + 1);
print($response);

//LOG
if ($debugDir != null) {
    $handle = fopen($debugDir . '/' . $messageid . '.log', 'w');
    fwrite($handle, "  ------ InfoCard SimpleSAMLphp Module LOG ------\n\n");
    fwrite($handle, "-- TIME: " . gmdate('Y-m-d') . ' ' . gmdate('H:i:s') . "\n");
    fwrite($handle, "-- MESSAGE ID: " . $messageid . "\n\n\n");
    fwrite($handle, "-- RST\n");
    fwrite($handle, $HTTP_RAW_POST_DATA);
    fwrite($handle, "\n\n\n-- RSTR\n");
    fwrite($handle, $response);
    fclose($handle);
}
