<?php

declare( strict_types = 1 );
namespace WaughJ\ContentSecurityPolicy;

class ContentSecurityPolicy
{
    public static function setPolicies( array $policies ) : void
    {
        header( 'Content-Security-Policy: ' . self::formatPolicies( $policies ) );
    }

    public static function testPolicies( array $policies ) : void
    {
        header( 'Content-Security-Policy-Report-Only: ' . self::formatPolicies( $policies ) );
    }

    private static function formatPolicies( array $policies ) : string
    {
        return implode
        (
            '; ',
            array_map
            (
                function( string $directive, array $directive_policies )
                {
                    return $directive . ' ' . implode( ' ', $directive_policies );
                },
                array_keys( $policies ),
                $policies
            )
        );
    }
}
