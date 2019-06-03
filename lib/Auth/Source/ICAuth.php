<?php

namespace SimpleSAML\Module\InfoCard\Auth\Source;

use Webmozart\Assert\Assert;

/*
* AUTHOR: Samuel Muñoz Hidalgo
* EMAIL: samuel.mh@gmail.com
* LAST REVISION: 22-DEC-08
* DESCRIPTION:
*  Authentication module.
*  Handles the login information
*  Infocard's claims are extracted passed as attributes.
*/

class ICAuth extends \SimpleSAML\Auth\Source
{
    //The string used to identify our states.
    const STAGEID = '\SimpleSAML\Module\core\Auth\UserPassBase.state';


    //The key of the AuthId field in the state.
    const AUTHID = '\SimpleSAML\Module\core\Auth\UserPassBase.AuthId';

    
    /**
     * @param array $info
     * @param array $config
     */
    public function __construct($info, $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);
    }
    
    
    /**
     * @param array &$state
     * @return void
     */
    public function authenticate(&$state)
    {
        // We are going to need the authId in order to retrieve this authentication source later
        $state[self::AUTHID] = $this->authId;
        $id = \SimpleSAML\Auth\State::saveState($state, self::STAGEID);
        $url = \SimpleSAML\Module::getModuleURL('InfoCard/login-infocard.php');
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($url, ['AuthState' => $id]);
    }
    

    /**
     * @param string $authStateId
     * @param string $xmlToken
     * @return string|null
     * @throws \Exception
     */
    public static function handleLogin($authStateId, $xmlToken)
    {
        Assert::string($authStateId);

        $config = \SimpleSAML\Configuration::getInstance();
        $autoconfig = $config->getConfig('config-login-infocard.php');
        $idp_key = $autoconfig->getValue('idp_key');
        $idp_pass = $autoconfig->getValue('idp_key_pass', null);
        $sts_crt = $autoconfig->getValue('sts_crt');
        $Infocard = $autoconfig->getValue('InfoCard');

        $infocard = new \SimpleSAML\Module\InfoCard\RP\InfoCard();
        $infocard->addIDPKey($idp_key, $idp_pass);
        $infocard->addSTSCertificate($sts_crt);    
        if (!$xmlToken) {
            \SimpleSAML\Logger::debug("XMLtoken: ".$xmlToken);
        } else {
            \SimpleSAML\Logger::debug("NOXMLtoken: ".$xmlToken);
            $claims = $infocard->process($xmlToken);
            if ($claims->isValid()) {
                $attributes = [];
                foreach ($Infocard['requiredClaims'] as $claim => $data) {
                    $attributes[$claim] = [$claims->$claim];
                }
                foreach ($Infocard['optionalClaims'] as $claim => $data) {
                    $attributes[$claim] = [$claims->$claim];
                }

                // Retrieve the authentication state
                $state = \SimpleSAML\Auth\State::loadState($authStateId, self::STAGEID);
                if (is_null($state)) {
                    throw new \SimpleSAML\Error\NoState();
                } else if (!array_key_exists(self::AUTHID, $state)) {
                    throw new \SimpleSAML\Error\AuthSource(self::AUTHID, "AuthSource not found in state");
                }
                // Find authentication source
                $source = \SimpleSAML\Auth\Source::getById($state[self::AUTHID]);
                if ($source === null) {
                    throw new \Exception('Could not find authentication source with id '.$state[self::AUTHID]);
                }            
                $state['Attributes'] = $attributes;    
                unset($infocard);
                unset($claims);
                \SimpleSAML\Auth\Source::completeAuth($state);
            } else {
                unset($infocard);
                unset($claims);
                return 'wrong_IC';
            }
        }
    }
}
