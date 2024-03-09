<?php

namespace ArchLinux\AntiSpam\Validator;

use MaxMind\Db\Reader;

/**
 * @codeCoverageIgnore
 */
class GeoIpReaderFactory
{
    public function __construct(private readonly Config $config)
    {
    }

    public function createReader(): Reader
    {
        return new Reader($this->config->getGeoIpDatabase());
    }
}
