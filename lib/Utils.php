<?php

namespace SimpleSAML\Module\InfoCard;

/*
 * AUTHOR: Samuel Muñoz Hidalgo
 * EMAIL: samuel.mh@gmail.com
 * LAST REVISION: 16-DEC-08
 * DESCRIPTION: some useful functions.
 */

class Utils
{
    /**
     * INPUT:  a PEM-encoded certificate
     * OUTPUT: a PEM-encoded certificate without the BEGIN and END headers
     *
     * @param string $cert
     * @return string
     */
    public static function takeCert($cert)
    {
        $begin = "CERTIFICATE-----";
        $end = "-----END";
        $pem = file_get_contents($cert);
        $pem = substr($pem, intval(strpos($pem, $begin)) + strlen($begin));
        $pem = substr($pem, 0, intval(strpos($pem, $end)));
        return str_replace("\n", "", $pem);
    }


    /**
     * INPUT:  a XML document
     * OUTPUT: a canonicalized XML document
     *
     * @param string $XMLdoc
     * @return string
     */
    public static function canonicalize($XMLdoc)
    {
        $dom = new \DOMDocument();
        $dom->loadXML($XMLdoc);
        return ($dom->C14N(true, false));
    }


    /**
     * @param string $cert
     * @return string
     */
    public static function thumbcert($cert)
    {
        return base64_encode(sha1(base64_decode($cert), true));
    }


    /**
     * INPUT:  a x509 certificate
     * OUTPUT: Common Name or a self issued value if no input is given
     * EXTRA: The output is used as issuer
     *
     * @param string $cert
     * @return string
     */
    public static function getIssuer($cert)
    {
        if ($cert == null) {
            return 'http://schemas.xmlsoap.org/ws/2005/05/identity/issuer/self';
        } else {
            $resource = file_get_contents($cert);
            $check_cert = openssl_x509_read($resource);
            $array = openssl_x509_parse($check_cert);
            openssl_x509_free($check_cert);
            $schema = $array['name'];
            $pattern = '/.*CN=/';
            $replacement = '';
            $CN = preg_replace($pattern, $replacement, $schema);
            return $CN;
        }
    }


    /**
     * INPUT: claims schema (string) and a DOMNodelist with the requested claims in uri style
     * OUTPUT: array of requested claims
     *
     * @param string $ICschema
     * @param \DOMNodeList $nodeList
     * @return array
     */
    public static function extractClaims($ICschema, $nodeList)
    {
        /**
         * Returns the Uri attribute from an attribute list
         * @param \DOMNamedNodeMap $attrList
         * @return string
         */
        function getUri($attrList)
        {
            $uri = null;
            $end = false;
            $i = 0;
            do {
                if ($i > $attrList->length) {
                    $end = true;
                } elseif (strcmp($attrList->item($i)->name, 'Uri') == 0) {
                    $end = true;
                    $uri = $attrList->item($i)->value;
                } else {
                    $i++;
                }
            } while (!$end);
            return $uri;
        }

        $requiredClaims = [];
        $schema = $ICschema . "/claims/";
        \SimpleSAML\Logger::debug("schema:   " . $schema);
        $pattern = '/\//';
        $replacement = '\/';
        $schema = '/' . preg_replace($pattern, $replacement, $schema) . '/';
        for ($i = 0; $i < ($nodeList->length); $i++) {
            $replacement = '';
            $uri = getUri($nodeList->item($i)->attributes);
            $claim = preg_replace($schema, $replacement, $uri);
            $requiredClaims[$i] = $claim;
            \SimpleSAML\Logger::debug("uri:   " . $uri);
            \SimpleSAML\Logger::debug("claim: " . $claim);
        }
        return $requiredClaims;
    }
}
