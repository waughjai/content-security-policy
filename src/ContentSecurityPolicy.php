<?php

declare( strict_types = 1 );
namespace WaughJ\ContentSecurityPolicy
{
	use WaughJ\UniqueValuesArray\UniqueValuesArray;

	class ContentSecurityPolicy
	{
		public function __construct( array $args = [], bool $default_self = true )
		{
			$this->settings = [];

			$default_value = ( $default_self ) ? [ "'self'" ] : [];
			foreach( self::DEFAULTS as $default_key )
			{
				$this->settings[ $default_key ] = new UniqueValuesArray( $default_value );
			}

			foreach ( $args as $arg_key => $arg_value )
			{
				if ( in_array( $arg_key, self::DEFAULTS ) )
				{
					if ( gettype( $arg_value ) === 'string' )
					{
						$arg_value = explode( ' ', $arg_value );
					}
					else if ( is_a( $arg_value, UniqueValuesArray::class ) )
					{
						$arg_value = $arg_value->getList();
					}

					$this->settings[ $arg_key ] = $this->settings[ $arg_key ]->addList( array_merge( $this->settings[ $arg_key ]->getList(), $arg_value ) );
				}
			}
		}

		public function submit() : void
		{
			header( $this->getHeaderString() );
		}

		public function getHeaderString() : string
		{
			return self::HEADER_NAME . ": " . $this->getAllHeaderLines();
		}

		public function getAllHeaderLines() : string
		{
			$lines = [];
			foreach ( $this->settings as $setting => $setting_value )
			{
				$lines[] = $this->getHeaderLine( $setting );
			}
			return implode( '; ', $lines );
		}

		public function getHeaderLine( string $type ) : string
		{
			return ( array_key_exists( $type, $this->settings ) )
				? implode( ' ', array_merge( [ $type ], $this->settings[ $type ]->getList() ) )
				: '';
		}

		public function getString( string $type ) : string
		{
			return ( array_key_exists( $type, $this->settings ) ) ? implode( ' ', $this->settings[ $type ]->getList() ) : "";
		}

		public function addItemToSrc( string $source_type, string $new_item ) : ContentSecurityPolicy
		{
			$settings = $this->settings;
			$settings[ $source_type ] = $settings[ $source_type ]->add( $new_item );
			return new ContentSecurityPolicy( $settings, false );
		}

		public function removeItemToSrc( string $source_type, string $remove_item ) : ContentSecurityPolicy
		{
			$settings = $this->settings;
			$settings[ $source_type ] = $settings[ $source_type ]->remove( $remove_item );
			return new ContentSecurityPolicy( $settings, false );
		}

		public function addListToSrc( string $source_type, array $add_list ) : ContentSecurityPolicy
		{
			$settings = $this->settings;
			$settings[ $source_type ] = $settings[ $source_type ]->addList( $add_list );
			return new ContentSecurityPolicy( $settings, false );
		}

		public function removeListToSrc( string $source_type, array $remove_list ) : ContentSecurityPolicy
		{
			$settings = $this->settings;
			$settings[ $source_type ] = $settings[ $source_type ]->removeList( $remove_list );
			return new ContentSecurityPolicy( $settings, false );
		}

		public function addMap( array $add_map ) : ContentSecurityPolicy
		{
			$settings = $this->settings;
			foreach ( $add_map as $key => $value )
			{
				if ( array_key_exists( $key, $settings ) )
				{
					$settings[ $key ] = $settings[ $key ]->addList( $value );
				}
			}
			return new ContentSecurityPolicy( $settings, false );
		}

		public function removeMap( array $remove_map ) : ContentSecurityPolicy
		{
			$settings = $this->settings;
			foreach ( $remove_map as $key => $value )
			{
				if ( array_key_exists( $key, $settings ) )
				{
					$settings[ $key ] = $settings[ $key ]->removeList( $value );
				}
			}
			return new ContentSecurityPolicy( $settings, false );
		}

		public function addUnsafeInline( string $source_type ) : ContentSecurityPolicy
		{
			return $this->addItemToSrc( $source_type, "'unsafe-inline'" );
		}

		public function removeUnsafeInline( string $source_type ) : ContentSecurityPolicy
		{
			return $this->removeItemToSrc( $source_type, "'unsafe-inline'" );
		}

		const HEADER_NAME = 'Content-Security-Policy';
		const DEFAULTS =
		[
			'default-src',
			'script-src',
			'style-src'
		];

		private $settings;
	}
}
