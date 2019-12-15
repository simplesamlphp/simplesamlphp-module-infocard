<?php

namespace SimpleSAML\Module\InfoCard;

/*
 * AUTHOR: Samuel Muñoz Hidalgo
 * EMAIL: samuel.mh@gmail.com
 * LAST REVISION: 13-FEB-09
 * DESCRIPTION: Functions for interconecting the system with your data model.
 *  Edit this functions to fit your needs
 */

class UserFunctions
{
    /**
     * Called by www/getinfocard.php and tokenservice.php
     * INPUT: credencial data (array), and type of credential
     * OUTPUT: true if the data is correct or false in other case
     *
     * @param array $credential
     * @param string $type
     * @return bool
     */
    public static function validateUser($credential, $type)
    {
        $status = false;
        switch ($type) {
            case 'UsernamePasswordCredential':
                if (
                    (strcmp($credential['username'], 'usuario') == 0)
                    && (strcmp($credential['password'], 'clave') == 0)
                ) {
                    $status = true;
                }
                break;
            case 'KerberosV5Credential':
                break;
            case 'X509V3Credential':
                break;
            case 'SelfIssuedCredential':
                // $credential['PPID']
                $status = true;
                break;
            default:
                break;
        }
        return $status;
    }
    
    
    
    /**
     * Called by www/tokenservice.php
     * INPUT: username, configured required claims, configured optional claims and requested claims
     * OUTPUT: array of claims wiht value and display tag.
     *
     * @param string $user
     * @param array $configuredRequiredClaims
     * @param array $configuredOptionalClaims
     * @param array $requiredClaims
     * @return array
     */
    public static function fillClaims($user, $configuredRequiredClaims, $configuredOptionalClaims, $requiredClaims)
    {
        $claimValues = [];
        foreach ($requiredClaims as $claim) {
            if (array_key_exists($claim, $configuredRequiredClaims)) {
                // The claim exists
                $claimValues[$claim]['value'] = "value-" . $claim;
                $claimValues[$claim]['displayTag'] = $configuredRequiredClaims[$claim]['displayTag'];
            } elseif (array_key_exists($claim, $configuredOptionalClaims)) {
                // The claim exists
                $claimValues[$claim]['value'] = "value-" . $claim;
                $claimValues[$claim]['displayTag'] = $configuredOptionalClaims[$claim]['displayTag'];
            } else {
                // The claim DOES NOT exist
                $claimValues[$claim]['value'] = "unknown-value";
                $claimValues[$claim]['displayTag'] = $claim;
            }
        }
        return $claimValues;
    }

    
    
    /**
     * INPUT: Unified way to create a single card identificator for a user
     * OUTPUT: User's card Identificator
     *
     * @param string $user
     * @return string
     */
    public static function generateCardID($user)
    {
        return 'urn:self-sts.uah.es:' . $user;
    }
    


    /**
     * Called by www/getinfocard.php
     * INPUT: valid username
     * OUTPUT: array containing user data to create its InfoCard
     *
     * @param string $user
     * @param string $UserCredential
     * @param string|null $ppid
     * @return array
     */
    public static function fillICdata($user, $UserCredential, $ppid = null)
    {
        $ICdata = [];
        $ICdata['CardId'] = \SimpleSAML\Module\InfoCard\UserFunctions::generateCardID($user);
        $ICdata['CardName'] = $user . "-SELFCREDENTIAL-IC";
        $ICdata['CardImage'] = '/var/simplesaml/modules/InfoCard/www/resources/demoimage.png';
        $ICdata['TimeExpires'] = "9999-12-31T23:59:59Z";
        
        //Credentials
        $ICdata['DisplayCredentialHint'] = 'Enter your password';
        switch ($UserCredential) {
            case 'UsernamePasswordCredential':
                $ICdata['UserName'] = $user;
                break;
            case 'KerberosV5Credential':
                break;
            case 'X509V3Credential':
                $ICdata['KeyIdentifier'] = null; //X509V3Credential
                break;
            case 'SelfIssuedCredential':
                $ICdata['PPID'] = $ppid;
                break;
            default:
                break;
        }
        return $ICdata;
    }
}
