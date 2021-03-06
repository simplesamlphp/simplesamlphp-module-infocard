<?php

/*
* AUTHOR: Samuel Muñoz Hidalgo
* EMAIL: samuel.mh@gmail.com
* LAST REVISION: 13-FEB-09
* DESCRIPTION:
*        Pretty form to get a managed InfoCard
*        User flow controller.
*        Displays the template and request a non null xmlToken
*/

// Load the configuration
$config = \SimpleSAML\Configuration::getInstance();
$autoconfig = $config->getConfig('config-login-infocard.php', 'logininfocard');

$Infocard = $autoconfig->getValue('InfoCard');


// Load the session of the current user
$session = \SimpleSAML\Session::getSessionFromRequest();

if (!array_key_exists('AuthState', $_REQUEST)) {
    \SimpleSAML\Logger::debug('NO AUTH STATE');
    \SimpleSAML\Logger::debug('ERROR: NO AUTH STATE');
    throw new \SimpleSAML\Error\BadRequest('Missing AuthState parameter.');
} else {
    $authStateId = $_REQUEST['AuthState'];
    SimpleSAML\Logger::debug('AUTH STATE:  ' . $authStateId);
}

$username = null;
$password = null;
$ICconfig = [];
$error = null;

$state = "validate";
if (array_key_exists('form', $_POST) && ($_POST['form'] != null)) {
    if (array_key_exists('username', $_POST) && ($_POST['username'] !== null)) {
        if (array_key_exists('password', $_POST) && ($_POST['password'] !== null)) {
            //Validation: Username/Password
            $username = $_POST['username'];
            $password = $_POST['password'];
            if (
                \SimpleSAML\Module\InfoCard\UserFunctions::validateUser(
                    ['username' => $username, 'password' => $password],
                    'UsernamePasswordCredential'
                )
            ) {
                $userCredential = $autoconfig->getValue('UserCredential');
                if (strcmp($userCredential, 'UsernamePasswordCredential') === 0) {
                    $ICconfig['InfoCard'] = $Infocard;
                    //SimpleSAML\Module\InfoCard\Utils::getIssuer($sts_crt);
                    $ICconfig['InfoCard']['issuer'] = $autoconfig->getValue('tokenserviceurl');
                    $ICconfig['tokenserviceurl'] = $autoconfig->getValue('tokenserviceurl');
                    $ICconfig['mexurl'] = $autoconfig->getValue('mexurl');
                    $ICconfig['sts_key'] = $autoconfig->getValue('sts_key');
                    $ICconfig['certificates'] = $autoconfig->getArray('certificates', []);
                    $ICconfig['UserCredential'] = $autoconfig->getValue('UserCredential');
                    
                    $ICdata = \SimpleSAML\Module\InfoCard\UserFunctions::fillICdata($username, $userCredential);
                    $IC = \SimpleSAML\Module\InfoCard\STS::createCard($ICdata, $ICconfig);
                    header("Content-Disposition: attachment; filename=\"" . $ICdata['CardName'] . ".crd\"");
                    header('Content-Type: application/x-informationcard');
                    header('Content-Length:' . strlen($IC));
                    echo $IC;
                    $state = 'end';
                } elseif (strcmp($userCredential, 'SelfIssuedCredential') === 0) {
                    /*
                    * VERY IMPORTANT:
                    * The STS is acting as a Relying Party to get the PPID in order to generate a
                    *  managed card with a self issued credential, that's why we use the STS
                    *  certificate private key to decrypt the token.
                    */
                    if (array_key_exists('xmlToken', $_POST) && ($_POST['xmlToken'] !== null)) {
                        SimpleSAML\Logger::debug('HAY XML TOKEN');
                        $token = new \SimpleSAML\Module\InfoCard\RP\InfoCard();
                        $idp_key = $autoconfig->getValue('sts_key');
                        $token->addIDPKey($idp_key);
                        $token->addSTSCertificate('');
                        $claims = $token->process($_POST['xmlToken']);
                        if (($claims->isValid()) && ($claims->privatepersonalidentifier != null)) {
                            $ppid = $claims->privatepersonalidentifier;
                            SimpleSAML\Logger::debug("PPID = $ppid");
                            $ICconfig['InfoCard'] = $Infocard;
                            //SimpleSAML\Module\InfoCard\Utils::getIssuer($sts_crt);
                            $ICconfig['InfoCard']['issuer'] = $autoconfig->getValue('tokenserviceurl');
                            $ICconfig['tokenserviceurl'] = $autoconfig->getValue('tokenserviceurl');
                            $ICconfig['mexurl'] = $autoconfig->getValue('mexurl');
                            $ICconfig['sts_key'] = $autoconfig->getValue('sts_key');
                            $ICconfig['certificates'] = $autoconfig->getValue('certificates');
                            $ICconfig['UserCredential'] = $autoconfig->getValue('UserCredential');

                            $ICdata = \SimpleSAML\Module\InfoCard\UserFunctions::fillICdata(
                                $username,
                                $userCredential,
                                $ppid
                            );
                            $IC = \SimpleSAML\Module\InfoCard\STS::createCard($ICdata, $ICconfig);
                            header('Content-Disposition: attachment; filename="' . $ICdata['CardName'] . '.crd"');
                            header('Content-Type: application/x-informationcard');
                            header('Content-Length:' . strlen($IC));
                            echo $IC;
                            $state = 'end';
                        } else {
                            \SimpleSAML\Logger::debug('Wrong Self-Issued card');
                            $error = 'wrong_IC';
                            $state = "selfIssued";
                        }
                    } else {
                        \SimpleSAML\Logger::debug('NO HAY XML TOKEN');
                        $error = null;
                        $state = "selfIssued";
                    }
                } else {
                    \SimpleSAML\Logger::debug(
                        'CONFIGURATION ERROR: UserCredential ' . $userCredential . ' NOT SUPPORTED'
                    );
                }
            } else {
                $error = 'Wrong_user_pass';
                \SimpleSAML\Logger::debug('WRONG username or password');
            }
        } else {
            $error = 'NO_password';
            \SimpleSAML\Logger::debug('NO PASSWORD');
        }
    } else {
        $error = 'NO_user';
        \SimpleSAML\Logger::debug('NO USERNAME');
    }
} else {
    $error = null;
}


unset($_POST); //Show the languages bar if reloaded

$t = new \SimpleSAML\XHTML\Template(
    $config,
    'InfoCard:temp-getcardform.php',
    'InfoCard:dict-InfoCard'
); //(configuracion, template, dictionary)
$t->data['header'] = 'SimpleSAMLphp: Get your Infocard';
$t->data['stateparams'] = ['AuthState' => $authStateId];
$t->data['InfoCard'] = $Infocard;

$cardGenerator = $autoconfig->getValue('CardGenerator');
$t->data['CardGenerator'] = $cardGenerator;

$help_desk_email_URL = $autoconfig->getValue('help_desk_email_URL');
$t->data['help_desk_email_URL'] = $help_desk_email_URL;

$contact_info_URL = $autoconfig->getValue('contact_info_URL');
$t->data['contact_info_URL'] = $contact_info_URL;

$t->data['error'] = $error;
$t->data['form'] = $state;

//For testing purposes
$t->data['username'] = $username;
$t->data['password'] = $password;

$t->show();
