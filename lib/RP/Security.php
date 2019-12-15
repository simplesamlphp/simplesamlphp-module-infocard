<?php

namespace SimpleSAML\Module\InfoCard\RP;

class Security extends \Zend_InfoCard_Xml_Security
{
    /**
     * Validates the signature of a provided XML block
     *
     * @param string $strXMLInput An XML block containing a Signature
     * @param string|null $sts_crt
     * @return string|false String if the signature validated, false otherwise
     * @throws \Exception
     */
    public static function validateXMLSignature($strXMLInput, $sts_crt = null)
    {
        if (!extension_loaded('openssl')) {
            throw new \Exception("You must have the openssl extension installed to use this class");
        }

        $sxe = simplexml_load_string($strXMLInput);

        if ($sts_crt !== null) {
            $sxe->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
            list($keyValue) = $sxe->xpath("//ds:Signature/ds:KeyInfo");
            $keyValue->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
            list($x509cert) = $keyValue->xpath("ds:X509Data/ds:X509Certificate");
            list($rsaKeyValue) = $keyValue->xpath("ds:KeyValue/ds:RSAKeyValue");
            // Extract the XMLToken issuer public key
            switch (true) {
                case isset($x509cert):
                    \SimpleSAML\Logger::debug("Public Key: x509cert");
                    $certificate = strval($x509cert);
                    $cert_issuer = "-----BEGIN CERTIFICATE-----\n" . wordwrap($certificate, 64, "\n", true) . "\n-----END CERTIFICATE-----";
                    if (!$t_key = openssl_pkey_get_public($cert_issuer)) {
                        throw new \Exception("Wrong token certificate");
                    }
                    $t_det = openssl_pkey_get_details($t_key);
                    $pem_issuer = $t_det['key'];
                    break;
                case isset($rsaKeyValue):
                    $rsaKeyValue->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
                    list($modulus) = $rsaKeyValue->xpath("ds:Modulus");
                    list($exponent) = $rsaKeyValue->xpath("ds:Exponent");
                    if (is_null($modulus) || is_null($exponent)) {
                        throw new \Exception("RSA Key Value not in Modulus/Exponent form");
                    }
                    $modulus = base64_decode(strval($modulus));
                    $exponent = base64_decode(strval($exponent));
                    $pem_issuer = self::_getPublicKeyFromModExp($modulus, $exponent);
                    break;
                default:
                    \SimpleSAML\Logger::debug("Public Key: Unknown");
                    throw new \Exception("Unable to determine or unsupported representation of the KeyValue block");
            }

            // Check isuer public key against configured one
            $checkcert = file_get_contents($sts_crt);
            $check_key = openssl_pkey_get_public($checkcert);
            $checkData = openssl_pkey_get_details($check_key);
            $pem_local = $checkData['key'];

            if (strcmp($pem_issuer, $pem_local) != 0) {
                \SimpleSAML\Logger::debug("Configured STS cert and received STS cert mismatch");
                openssl_free_key($check_key);
                throw new \Exception("Configured STS cert and received STS cert mismatch");
            }

            // Validate XML signature
            $sxe->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

            list($canonMethod) = $sxe->xpath("//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod");
            switch (strval($canonMethod['Algorithm'])) {
                case self::CANONICAL_METHOD_C14N_EXC:
                    break;
                default:
                    throw new \Exception("Unknown or unsupported CanonicalizationMethod Requested");
            }

            list($signatureMethod) = $sxe->xpath("//ds:Signature/ds:SignedInfo/ds:SignatureMethod");
            switch (strval($signatureMethod['Algorithm'])) {
                case self::SIGNATURE_METHOD_SHA1:
                    break;
                default:
                    throw new \Exception("Unknown or unsupported SignatureMethod Requested");
            }

            list($digestMethod) = $sxe->xpath("//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod");
            switch (strval($digestMethod['Algorithm'])) {
                case self::DIGEST_METHOD_SHA1:
                    break;
                default:
                    throw new \Exception("Unknown or unsupported DigestMethod Requested");
            }

            $base64DecodeSupportsStrictParam = version_compare(PHP_VERSION, '5.2.0', '>=');

            list($digestValue) = $sxe->xpath("//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue");
            if ($base64DecodeSupportsStrictParam) {
                $dValue = base64_decode(strval($digestValue), true);
            } else {
                $dValue = base64_decode(strval($digestValue));
            }

            list($signatureValueElem) = $sxe->xpath("//ds:Signature/ds:SignatureValue");
            if ($base64DecodeSupportsStrictParam) {
                $signatureValue = base64_decode(strval($signatureValueElem), true);
            } else {
                $signatureValue = base64_decode(strval($signatureValueElem));
            }

            $transformer = new \Zend_InfoCard_Xml_Security_Transform();

            $transforms = $sxe->xpath("//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform");
            while (list(, $transform) = each($transforms)) {
                $transformer->addTransform(strval($transform['Algorithm']));
            }
            $transformed_xml = $transformer->applyTransforms($strXMLInput);
            $transformed_xml_binhash = pack("H*", sha1($transformed_xml));
            if ($transformed_xml_binhash != $dValue) {
                throw new \Exception("Locally Transformed XML (" . $transformed_xml_binhash . ") does not match XML Document  (" . $dValue . "). Cannot Verify Signature");
            }

            $transformer = new \Zend_InfoCard_Xml_Security_Transform();
            $transformer->addTransform(strval($canonMethod['Algorithm']));
            list($signedInfo) = $sxe->xpath("//ds:Signature/ds:SignedInfo");

            $signedInfoXML = self::addNamespace($signedInfo, "http://www.w3.org/2000/09/xmldsig#");
            \SimpleSAML\Logger::debug("canonicalizo " . $signedInfoXML);
            $canonical_signedinfo = $transformer->applyTransforms($signedInfoXML);
            if (openssl_verify($canonical_signedinfo, $signatureValue, $check_key) === 1) {
                list($reference) = $sxe->xpath("//ds:Signature/ds:SignedInfo/ds:Reference");
                openssl_free_key($check_key);
                return strval($reference['URI']);
            } else {
                openssl_free_key($check_key);
                throw new \Exception("Could not validate the XML signature");
            }
        } else {
            $sxe->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
            list($reference) = $sxe->xpath("//ds:Signature/ds:SignedInfo/ds:Reference");
            return strval($reference['URI']);
        }
    }


    /**
     * @param \SimpleXMLElement $xmlElem
     * @param string $ns
     * @return string
     */
    private static function addNamespace($xmlElem, $ns)
    {
        $schema = '.*<[^<]*SignedInfo[^>]*' . $ns . '.*>.*';
        $pattern = '/\//';
        $replacement = '\/';
        $nspattern = '/' . preg_replace($pattern, $replacement, $schema) . '/';
        if (preg_match($nspattern, $xmlElem->asXML()) > 0) { //M$ Cardspaces
            $xml = $xmlElem->asXML();
        } else { //Digitalme
            $xmlElem->addAttribute('DS_NS', $ns);
            $xml = $xmlElem->asXML();
            if (preg_match("/<(\w+)\:\w+/", $xml, $matches)) {
                $prefix = $matches[1];
                $xml = str_replace("DS_NS", "xmlns:" . $prefix, $xml);
            } else {
                $xml = str_replace("DS_NS", "xmlns", $xml);
            }
        }
        return $xml;
    }
}
