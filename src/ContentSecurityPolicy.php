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
			$this->default_self = $default_self;

			$default_value = ( $default_self ) ? [ "'self'" ] : [];
			foreach ( $args as $arg_key => $arg_value )
			{
				if ( in_array( $arg_key, self::TYPES ) )
				{
					$this->settings[ $arg_key ] = new UniqueValuesArray( $default_value );

					if ( in_array( $arg_key, self::TYPES ) )
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
				if ( !empty( $setting_value->getList() ) )
				{
					$lines[] = $this->getHeaderLine( $setting );
				}
			}
			return implode( '; ', $lines );
		}

		public function getHeaderLine( string $type ) : string
		{
			return ( !empty( $this->settings[ $type ]->getList() ) )
				? implode( ' ', array_merge( [ $type ], $this->settings[ $type ]->getList() ) )
				: '';
		}

		public function getString( string $type ) : string
		{
			return ( array_key_exists( $type, $this->settings ) ) ? implode( ' ', $this->settings[ $type ]->getList() ) : "";
		}

		public function addItemToSrc( string $source_type, string $new_item ) : ContentSecurityPolicy
		{
			return $this->changeItemToSrc( 'add', 'string', $source_type, $new_item );
		}

		public function removeItemToSrc( string $source_type, string $remove_item ) : ContentSecurityPolicy
		{
			return $this->changeItemToSrc( 'remove', 'string', $source_type, $remove_item );
		}

		public function addListToSrc( string $source_type, array $add_list ) : ContentSecurityPolicy
		{
			return $this->changeItemToSrc( 'addList', 'array', $source_type, $add_list );
		}

		public function removeListToSrc( string $source_type, array $remove_list ) : ContentSecurityPolicy
		{
			return $this->changeItemToSrc( 'removeList', 'array', $source_type, $remove_list );
		}

		public function addMap( array $change_map ) : ContentSecurityPolicy
		{
			return $this->changeMap
			(
				$change_map,
				$function = function( UniqueValuesArray $setting, array $value )
				{
					$setting = $setting->addList( $value );
					if ( $this->default_self )
					{
						$setting = $setting->add( "'self'" );
					}
					return $setting;
				},
				$this->default_self
			);
		}

		public function removeMap( array $change_map ) : ContentSecurityPolicy
		{
			return $this->changeMap
			(
				$change_map,
				function( UniqueValuesArray $setting, array $value )
				{
					return $setting->removeList( $value );
				},
				false
			);
		}

		public function addUnsafeInline( string $source_type ) : ContentSecurityPolicy
		{
			return $this->addItemToSrc( $source_type, "'unsafe-inline'" );
		}

		public function removeUnsafeInline( string $source_type ) : ContentSecurityPolicy
		{
			return $this->removeItemToSrc( $source_type, "'unsafe-inline'" );
		}

		private function changeItemToSrc( string $function_name, string $variable_type, string $source_type, $change_item ) : ContentSecurityPolicy
		{
			assert( gettype( $change_item ) === $variable_type );
			if ( in_array( $source_type, self::TYPES ) )
			{
				$settings = $this->settings;
				if ( !array_key_exists( $source_type, $settings ) )
				{
					$settings[ $source_type ] = new UniqueValuesArray([]);
				}
				$settings[ $source_type ] = [ $settings[ $source_type ], $function_name ]( $change_item );
				return new ContentSecurityPolicy( $settings, $this->default_self );
			}
			return $this;
		}

		private function changeMap( array $change_map, callable $function, bool $force_default_self ) : ContentSecurityPolicy
		{
			$settings = $this->settings;
			foreach ( $change_map as $key => $value )
			{
				if ( in_array( $key, self::TYPES ) )
				{
					if ( !array_key_exists( $key, $settings ) )
					{
						$settings[ $key ] = new UniqueValuesArray([]);
					}
					$settings[ $key ] = $function( $settings[ $key ], $value );
				}
			}
			return new ContentSecurityPolicy( $settings, $force_default_self );
		}

		const HEADER_NAME = 'Content-Security-Policy';
		const TYPES =
		[
			'default-src',
			'script-src',
			'style-src',
			'img-src',
			'font-src',
			'media-src',
			'object-src',
			'form-action',
			'connect-src',
			'frame-src',
			'child-src',
			'worker-src',
			'manifest-src'
		];

		private $settings;
		private $default_self;
	}
}
