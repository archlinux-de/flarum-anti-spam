COMPOSER := 'composer --no-interaction'

install-latest:
	{{COMPOSER}} update --prefer-stable

install-lowest:
	{{COMPOSER}} update --prefer-lowest

test:
	{{COMPOSER}} validate --strict --no-check-lock
	vendor/bin/phpcs
	vendor/bin/phpstan analyse --memory-limit=-1
	{{COMPOSER}} test:unit

test-integration:
	{{COMPOSER}} test:integration

test-coverage:
	php -d zend_extension=xdebug -d xdebug.mode=coverage -d memory_limit=-1 vendor/bin/phpunit -c tests/phpunit.unit.xml --coverage-html coverage
