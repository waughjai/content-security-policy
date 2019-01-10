<?php

use PHPUnit\Framework\TestCase;
use WaughJ\ContentSecurityPolicy\ContentSecurityPolicy;

class ContentSecurityPolicyTest extends TestCase
{
	public function testDefault()
	{
		$csp = new ContentSecurityPolicy();
		$this->assertEquals( $csp->getString( 'default-src' ), "" );
	}

	public function testEverything()
	{
		$csp = new ContentSecurityPolicy( self::ARGUMENTS );
		$this->assertEquals( "'self' https://www.google.com", $csp->getString( 'default-src' ) );
		$this->assertEquals( "", $csp->getString( 'style-src' ) );
		$this->assertEquals( "", $csp->getString( 'not-here' ) );
	}

	public function testUnsafeInline()
	{
		$csp = new ContentSecurityPolicy( self::ARGUMENTS );
		$csp = $csp->addUnsafeInline( 'script-src' );
		$this->assertEquals( "'self' https://www.google.com", $csp->getString( 'default-src' ) );
		$this->assertEquals( "'self' https://www.google.com 'unsafe-inline'", $csp->getString( 'script-src' ) );
		$csp = $csp->removeUnsafeInline( 'script-src' );
		$this->assertEquals( "'self' https://www.google.com", $csp->getString( 'script-src' ) );
	}

	public function testAddAndRemove()
	{
		$csp = new ContentSecurityPolicy( self::ARGUMENTS );
		$csp = $csp->addItemToSrc( 'default-src', 'https://www.facebook.com' );
		$this->assertEquals( "'self' https://www.google.com https://www.facebook.com", $csp->getString( 'default-src' ) );
		$csp = $csp->removeItemToSrc( 'default-src', 'https://www.google.com' );
		$this->assertEquals( "'self' https://www.facebook.com", $csp->getString( 'default-src' ) );
		$csp = $csp->addListToSrc( 'default-src', [ 'https://www.example.com', 'https://www.something.com', 'https://www.facebook.com' ] );
		$this->assertEquals( "'self' https://www.facebook.com https://www.example.com https://www.something.com", $csp->getString( 'default-src' ) );
		$csp = $csp->removeListToSrc( 'default-src', [ 'https://www.something.com', 'https://www.facebook.com' ] );
		$this->assertEquals( "'self' https://www.example.com", $csp->getString( 'default-src' ) );
		$csp = $csp->addItemToSrc( 'style-src', 'https://www.facebook.com' );
		$this->assertEquals( "'self' https://www.facebook.com", $csp->getString( 'style-src' ) );
		$csp = $csp->addListToSrc( 'img-src', [ 'https://www.example.com', 'https://www.something.com' ] );
		$this->assertEquals( "'self' https://www.example.com https://www.something.com", $csp->getString( 'img-src' ) );
	}

	public function testAddAndRemoveMap()
	{
		$csp = new ContentSecurityPolicy( self::ARGUMENTS );
		$csp = $csp->addMap( [ 'default-src' => [ 'https://www.example.com', 'https://www.cool.com' ], 'style-src' => [ 'https://www.example.com' ], 'shuuba' => [ 'alkjdfkjsd' ] ]);
		$this->assertEquals( "'self' https://www.google.com https://www.example.com https://www.cool.com", $csp->getString( 'default-src' ) );
		$this->assertEquals( "'self' https://www.example.com", $csp->getString( 'style-src' ) );
		$csp = $csp->removeMap( [ 'default-src' => [ 'https://www.example.com', 'https://www.google.com' ], 'style-src' => [ "'self'", "https://www.nothing.com" ], 'shuuba' => [ 'alkjdfkjsd' ] ]);
		$this->assertEquals( "'self' https://www.cool.com", $csp->getString( 'default-src' ) );
		$this->assertEquals( "https://www.example.com", $csp->getString( 'style-src' ) );
	}

	public function testHeaderString()
	{
		$csp = new ContentSecurityPolicy( self::ARGUMENTS );
		$this->assertEquals( "Content-Security-Policy: default-src 'self' https://www.google.com; script-src 'self' https://www.google.com", $csp->getHeaderString() );
	}

	public function testInvalidSrcType()
	{
		$csp = new ContentSecurityPolicy( [ 'milktoast' => [ 'suppa' ] ] );
		$this->assertEquals( "", $csp->getString( 'milktoast' ) );
		$csp = $csp->addItemToSrc( 'milktoast', 'https://www.facebook.com' );
		$this->assertEquals( "", $csp->getString( 'milktoast' ) );
		$csp = $csp->removeItemToSrc( 'milktoast', 'https://www.google.com' );
		$this->assertEquals( "", $csp->getString( 'milktoast' ) );
		$csp = $csp->addListToSrc( 'milktoast', [ 'https://www.example.com', 'https://www.something.com', 'https://www.facebook.com' ] );
		$this->assertEquals( "", $csp->getString( 'milktoast' ) );
		$csp = $csp->removeListToSrc( 'milktoast', [ 'https://www.something.com', 'https://www.facebook.com' ] );
		$this->assertEquals( "", $csp->getString( 'milktoast' ) );
		$csp = $csp->addMap( [ 'default-src' => [ 'https://www.example.com', 'https://www.cool.com' ], 'style-src' => [ 'https://www.example.com' ], 'milktoast' => [ 'alkjdfkjsd' ] ]);
		$this->assertEquals( "", $csp->getString( 'milktoast' ) );
		$csp = $csp->removeMap( [ 'default-src' => [ 'https://www.example.com', 'https://www.google.com' ], 'style-src' => [ "'self'", "https://www.nothing.com" ], 'milktoast' => [ 'alkjdfkjsd' ] ]);
		$this->assertEquals( "", $csp->getString( 'milktoast' ) );
		$this->assertNotContains( "milktoast", $csp->getHeaderString() );
		$this->assertEquals( "Content-Security-Policy: default-src 'self' https://www.cool.com; style-src https://www.example.com", $csp->getHeaderString() );
	}

	const ARGUMENTS =
	[
		'default-src' => [ 'https://www.google.com' ],
		'script-src' => [ 'https://www.google.com' ]
	];
}
