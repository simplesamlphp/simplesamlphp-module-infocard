<?php

namespace SimpleSAML\Module\InfoCard\RP;

/*
 * COAUTHOR: Samuel Muñoz Hidalgo
 * EMAIL: samuel.mh@gmail.com
 * LAST REVISION: 22-DEC-08
 * DESCRIPTION: Zend Infocard libraries added sts certificate check
 */

class InfoCard
{
    public const XENC_NS = "http://www.w3.org/2001/04/xmlenc#";
    public const XENC_ELEMENT_TYPE = "http://www.w3.org/2001/04/xmlenc#Element";
    public const XENC_ENC_ALGO = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    public const XENC_KEYINFO_ENC_ALGO = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    public const DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    public const DSIG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    public const DSIG_ENVELOPED_SIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    public const DSIG_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

    public const CANON_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#";

    public const WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public const WSSE_KEYID_VALUE_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1";

    public const XMLSOAP_SELF_ISSUED = "http://schemas.xmlsoap.org/ws/2005/05/identity/issuer/self";

    public const XMLSOAP_CLAIMS_NS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

    public const SAML_ASSERTION_1_0_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
    public const SAML_ASSERTION_1_1_NS = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";

    /** @var string $private_key_file */
    protected $private_key_file = '';

    /** @var string $public_key_file */
    protected $public_key_file = '';

    /** @var string|null $password */
    protected $password;

    /** @var \SimpleXMLElement $_xml */
    protected $sxml;

    /** @var string $sts_crt */
    protected $sts_crt = '';


    /**
     * Constructor
     */
    public function __construct()
    {
        if (!extension_loaded('mcrypt')) {
            throw new \Exception("Use of the InfoCard component requires the mcrypt extension to be enabled in PHP");
        }

        if (!extension_loaded('openssl')) {
            throw new \Exception("Use of the InfoCard component requires the openssl extension to be enabled in PHP");
        }
    }


    /**
     * @param string $sts_crt
     * @return void
     * @throws \Exception
     */
    public function addSTSCertificate($sts_crt)
    {
        $this->sts_crt = $sts_crt;
        if (($sts_crt == null) || (strcmp($sts_crt, '') == 0)) {
            \SimpleSAML\Logger::debug('WARNING: No STS certificate is set, ALL TOKENS WILL BE ACCEPTED');
        } elseif ((!file_exists($sts_crt)) || (!is_readable($sts_crt))) {
            throw new \Exception("STS certificate is not readable");
        }
    }


    /**
     * @param string $private_key_file
     * @param string|null $password
     * @return void
     * @throws \Exception
     */
    public function addIDPKey($private_key_file, $password = null)
    {
        $this->private_key_file = $private_key_file;
        $this->password = $password;

        if (!file_exists($this->private_key_file)) {
            throw new \Exception("Private key file does not exists");
        }
    
        if (!is_readable($this->private_key_file)) {
            throw new \Exception("Private key file is not readable");
        }
    }


    /**
     * Function not used $public_key_file is not used
     *
     * @param string $private_key_file
     * @param string $public_key_file
     * @param string|null $password
     * @return void
     * @throws \Exception
     */
    public function addCertificatePair($private_key_file, $public_key_file, $password = null)
    {
        $this->private_key_file = $private_key_file;
        $this->public_key_file = $public_key_file;
        $this->password = $password;

        if (!file_exists($this->private_key_file)) {
            throw new \Exception("Private key file does not exists");
        }
    
        if (!is_readable($this->private_key_file)) {
            throw new \Exception("Private key file is not readable");
        }

        if (!file_exists($this->public_key_file)) {
            throw new \Exception("Public key file does not exists");
        }

        if (!is_readable($this->public_key_file)) {
            throw new \Exception("Public key file is not readable");
        }
    }


    /**
     * @param string $xmlToken
     * @return \Zend_InfoCard_Claims
     */
    public function process($xmlToken)
    {
        if (strpos($xmlToken, "EncryptedData") === false) {
            \SimpleSAML\Logger::debug('IC: UNsecureToken');
            return $this->processUnSecureToken($xmlToken);
        } else {
            \SimpleSAML\Logger::debug('IC: secureToken');
            return $this->processSecureToken($xmlToken);
        }
    }


    /**
     * @param string $xmlToken
     * @return \Zend_InfoCard_Claims
     */
    private function processSecureToken($xmlToken)
    {
        $retval = new \Zend_InfoCard_Claims();

        try {
            $result = \simplexml_load_string($xmlToken);
            if ($result === false) {
                throw new \Exception('Unable to parse XML input');
            }
            $this->sxml = \simplexml_load_string($xmlToken);
            $decryptedToken = $this->decryptToken($xmlToken);
        } catch (\Exception $e) {
            \SimpleSAML\Logger::debug('ProcSecToken ' . $e);
            $retval->setError('Failed to extract assertion document');
            $retval->setCode(\Zend_InfoCard_Claims::RESULT_PROCESSING_FAILURE);
            return $retval;
        }

        try {
            $assertions = $this->getAssertions($decryptedToken);
        } catch (\Exception $e) {
            $retval->setError('Failure processing assertion document');
            $retval->setCode(\Zend_InfoCard_Claims::RESULT_PROCESSING_FAILURE);
            return $retval;
        }

        try {
            $reference_id = $this->validateSignature($assertions);
            $this->checkConditions($reference_id, $assertions);
        } catch (\Exception $e) {
            $retval->setError($e->getMessage());
            $retval->setCode(\Zend_InfoCard_Claims::RESULT_VALIDATION_FAILURE);
            return $retval;
        }

        return $this->getClaims($retval, $assertions);
    }


    /**
     * @param string $xmlToken
     * @return \Zend_InfoCard_Claims
     */
    private function processUnsecureToken($xmlToken)
    {
        $retval = new \Zend_InfoCard_Claims();

        try {
            $assertions = $this->getAssertions($xmlToken);
        } catch (\Exception $e) {
            $retval->setError('Failure processing assertion document');
            $retval->setCode(\Zend_InfoCard_Claims::RESULT_PROCESSING_FAILURE);
            return $retval;
        }

        return $this->getClaims($retval, $assertions);
    }


    /**
     * @param \Zend_InfoCard_Xml_Assertion_Saml $assertions
     * @return string
     * @throws \Exception
     */
    private function walidateSignature($assertions)
    {
        //include_once 'Zend_InfoCard_Xml_Security.php';
        $as = $assertions->asXML();
        $reference_id = \Zend_InfoCard_Xml_Security::validateXMLSignature(is_string($as) ? $as : '', $this->sts_crt);
        return $reference_id;
    }


    /**
     * @param string $reference_id
     * @param \Zend_InfoCard_Xml_Assertion_Saml $assertions
     * @return void
     * @throws \Exception
     */
    private function checkConditions($reference_id, $assertions)
    {
        if ($reference_id[0] == '#') {
            $reference_id = substr($reference_id, 1);
        } else {
            throw new \Exception("Reference of document signature does not reference the local document");
        }

        if ($reference_id != $assertions->getAssertionID()) {
            throw new \Exception("Reference of document signature does not reference the local document");
        }

        $conditions = $assertions->getConditions();
        if (is_array($condition_error = $assertions->validateConditions($conditions))) {
            throw new \Exception(
                "Conditions of assertion document are not met: {$condition_error[1]} ({$condition_error[0]})"
            );
        }
    }


    /**
     * @param \Zend_InfoCard_Claims $retval
     * @param \Zend_InfoCard_Xml_Assertion_Saml $assertions
     * @return \Zend_InfoCard_Claims
     */
    private function getClaims($retval, $assertions)
    {
        $attributes = $assertions->getAttributes();
        $retval->setClaims($attributes);
        if ($retval->getCode() == 0) {
            $retval->setCode(\Zend_InfoCard_Claims::RESULT_SUCCESS);
        }

        return $retval;
    }


    /**
     * @param string $strXmlData
     * @return \Zend_InfoCard_Xml_Assertion_Saml
     * @throws \Exception
     */
    private function getAssertions($strXmlData)
    {
        $sxe = \simplexml_load_string($strXmlData);
        $namespaces = $sxe->getDocNameSpaces();
        foreach ($namespaces as $namespace) {
            switch ($namespace) {
                case self::SAML_ASSERTION_1_0_NS:
                    //include_once 'Zend_InfoCard_Xml_Assertion_Saml.php';
                    /** @var \Zend_InfoCard_Xml_Assertion_Saml $result */
                    $result = \simplexml_load_string($strXmlData, 'Zend_InfoCard_Xml_Assertion_Saml');
                    return $result;
            }
        }

        throw new \Exception("Unable to determine Assertion type by Namespace");
    }


    /**
     * @param string $xmlToken
     * @return string
     * @throws \Exception
     */
    private function decryptToken($xmlToken)
    {
        if ($this->sxml['Type'] !== self::XENC_ELEMENT_TYPE) {
            throw new \Exception("Unknown EncryptedData type found");
        }

        $this->sxml->registerXPathNamespace('enc', self::XENC_NS);
        list($encryptionMethod) = $this->sxml->xpath("//enc:EncryptionMethod");
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($encryptionMethod instanceof \SimpleXMLElement)) {
            throw new \Exception("EncryptionMethod node not found");
        }

        $encMethodDom = \dom_import_simplexml($encryptionMethod);
        /** @psalm-suppress TypeDoesNotContainType */
        if (!$encMethodDom instanceof \DOMElement) {
            throw new \Exception("Failed to create DOM from EncryptionMethod node");
        }

        if (!$encMethodDom->hasAttribute("Algorithm")) {
            throw new \Exception(
                "Unable to determine the encryption algorithm in the Symmetric enc:EncryptionMethod XML block"
            );
        }

        $algo = $encMethodDom->getAttribute("Algorithm");
        if ($algo != self::XENC_ENC_ALGO) {
            throw new \Exception("Unsupported encryption algorithm");
        }

        $this->sxml->registerXPathNamespace('ds', self::DSIG_NS);
        list($keyInfo) = $this->sxml->xpath("ds:KeyInfo");
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($keyInfo instanceof \SimpleXMLElement)) {
            throw new \Exception("KeyInfo node not found");
        }

        $keyInfo->registerXPathNamespace('enc', self::XENC_NS);
        list($encryptedKey) = $keyInfo->xpath("enc:EncryptedKey");
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($encryptedKey instanceof \SimpleXMLElement)) {
            throw new \Exception("EncryptedKey element not found in KeyInfo");
        }

        $encryptedKey->registerXPathNamespace('enc', self::XENC_NS);
        list($keyInfoEncryptionMethod) = $encryptedKey->xpath("enc:EncryptionMethod");
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($keyInfoEncryptionMethod instanceof \SimpleXMLElement)) {
            throw new \Exception("EncryptionMethod element not found in EncryptedKey");
        }

        $keyInfoEncMethodDom = dom_import_simplexml($keyInfoEncryptionMethod);
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($keyInfoEncMethodDom instanceof \DOMElement)) {
            throw new \Exception("Failed to create DOM from EncryptionMethod node");
        }

        if (!$keyInfoEncMethodDom->hasAttribute("Algorithm")) {
            throw new \Exception(
                "Unable to determine the encryption algorithm in the Symmetric enc:EncryptionMethod XML block"
            );
        }

        $keyInfoEncMethodAlgo = $keyInfoEncMethodDom->getAttribute("Algorithm");
        if ($keyInfoEncMethodAlgo != self::XENC_KEYINFO_ENC_ALGO) {
            throw new \Exception("Unsupported encryption algorithm");
        }

        $encryptedKey->registerXPathNamespace('ds', self::DSIG_NS);
        $encryptedKey->registerXPathNamespace('wsse', self::WSSE_NS);
        list($keyIdentifier) = $encryptedKey->xpath("ds:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier");
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($keyIdentifier instanceof \SimpleXMLElement)) {
            throw new \Exception("KeyInfo/SecurityTokenReference/KeyIdentifier node not found in KeyInfo");
        }

        $keyIdDom = dom_import_simplexml($keyIdentifier);
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($keyIdDom instanceof \DOMElement)) {
            throw new \Exception("Failed to create DOM from KeyIdentifier node");
        }

        if (!$keyIdDom->hasAttribute("ValueType")) {
            throw new \Exception("Unable to determine ValueType of KeyIdentifier");
        }

        $valueType = $keyIdDom->getAttribute("ValueType");
        if ($valueType != self::WSSE_KEYID_VALUE_TYPE) {
            throw new \Exception("Unsupported KeyIdentifier ValueType");
        }

        list($cipherValue) = $encryptedKey->xpath("enc:CipherData/enc:CipherValue");
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($cipherValue instanceof \SimpleXMLElement)) {
            throw new \Exception("CipherValue node found in EncryptedKey");
        }

        $keyCipherValueBase64Decoded = base64_decode($cipherValue->__toString(), true);

        if (is_null($this->password)) {
            $private_key = openssl_pkey_get_private(strval(file_get_contents($this->private_key_file)));
        } else {
            $private_key = openssl_pkey_get_private(
                strval(file_get_contents($this->private_key_file)),
                $this->password
            );
        }
        if (!$private_key) {
            throw new \Exception("Unable to load private key");
        }
    
        $result = openssl_private_decrypt(
            $keyCipherValueBase64Decoded,
            $symmetricKey,
            $private_key,
            \OPENSSL_PKCS1_OAEP_PADDING
        );
        openssl_free_key($private_key);

        if (!$result) {
            throw new \Exception("Unable to decrypt symmetric key");
        }

        list($cipherValue2) = $this->sxml->xpath("enc:CipherData/enc:CipherValue");
        /** @psalm-suppress TypeDoesNotContainType */
        if (!($cipherValue2 instanceof \SimpleXMLElement)) {
            throw new \Exception("CipherValue node found in EncryptedData");
        }

        $keyCipherValueBase64Decoded = base64_decode($cipherValue2->__toString(), true);

        $mcrypt_iv = substr($keyCipherValueBase64Decoded, 0, 16);
        $keyCipherValueBase64Decoded = substr($keyCipherValueBase64Decoded, 16);
        $decrypted = mcrypt_decrypt(
            \MCRYPT_RIJNDAEL_128,
            $symmetricKey,
            $keyCipherValueBase64Decoded,
            \MCRYPT_MODE_CBC,
            $mcrypt_iv
        );

        if (!$decrypted) {
            throw new \Exception("Unable to decrypt token");
        }

        $decryptedLength = strlen($decrypted);
        $paddingLength = substr($decrypted, $decryptedLength - 1, 1);
        $decrypted = substr($decrypted, 0, $decryptedLength - ord($paddingLength));
        $decrypted = rtrim($decrypted, "\0");

        return $decrypted;
    }
}
