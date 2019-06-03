<?php

/*
* AUTHOR: Samuel Muñoz Hidalgo
* EMAIL: samuel.mh@gmail.com
* LAST REVISION: 13-FEB-09
* DESCRIPTION:
*        User flow controller.
*        Displays the template and request a non null xmlToken
*/



// Load the configuration
$config = \SimpleSAML\Configuration::getInstance();
$autoconfig = \SimpleSAML\Configuration::getConfig('config-login-infocard.php');

$server_key = $autoconfig->getValue('server_key');
$server_crt = $autoconfig->getValue('server_crt');
$IClogo = $autoconfig->getValue('IClogo');
$Infocard = $autoconfig->getValue('InfoCard');
$cardGenerator = $autoconfig->getValue('CardGenerator');
$sts_crt = $autoconfig->getValue('sts_crt');
$help_desk_email_URL = $autoconfig->getValue('help_desk_email_URL');
$contact_info_URL = $autoconfig->getValue('contact_info_URL');


// Load the session of the current user
$session = \SimpleSAML\Session::getSessionFromRequest();


if (!array_key_exists('AuthState', $_REQUEST)) {
    \SimpleSAML\Logger::debug('NO AUTH STATE');
    \SimpleSAML\Logger::debug('ERROR: NO AUTH STATE');
    throw new \SimpleSAML\Error\BadRequest('Missing AuthState parameter.');
} else {
    $authStateId = $_REQUEST['AuthState'];
    \SimpleSAML\Logger::debug('AUTH STATE:  '.$authStateId);
}

if (array_key_exists('xmlToken', $_POST) && ($_POST['xmlToken'] != null)) {
    SimpleSAML\Logger::debug('HAY XML TOKEN');
    $error = \SimpleSAML\Module\InfoCard\Auth\Source\ICAuth::handleLogin($authStateId, $_POST['xmlToken']);
} else {
    SimpleSAML\Logger::debug('NO HAY XML TOKEN');
    $error = null;
}

unset($_POST); //Show the languages bar if reloaded
 
//Login Page
$t = new \SimpleSAML\XHTML\Template($config, 'InfoCard:temp-login.php', 'InfoCard:dict-InfoCard'); //(configuracion, template, diccionario)
$t->data['header'] = 'SimpleSAMLphp: Infocard login';
$t->data['stateparams'] = ['AuthState' => $authStateId];
$t->data['IClogo'] = $IClogo;
$t->data['InfoCard'] = $Infocard;
$t->data['InfoCard']['issuer'] = $autoconfig->getValue('tokenserviceurl'); //SimpleSAML\Module\InfoCard\Utils::getIssuer($sts_crt);
$t->data['CardGenerator'] = $cardGenerator;
$t->data['help_desk_email_URL'] = $help_desk_email_URL;
$t->data['contact_info_URL'] = $contact_info_URL;
$t->data['error'] = $error;
$t->show();
exit();
