<?php

namespace ArchLinux\AntiSpam\Validator;

use Flarum\Foundation\Config;
use Flarum\Foundation\ValidationException;
use Flarum\User\Event\Saving;
use MaxMind\Db\Reader;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;

class RegistrationHandler
{
    private string $geoIpDatabase = '/usr/share/GeoIP/GeoLite2-Country.mmdb';
    private Reader $geoIpReader;

    private array $userAgentAllowList = [];
    private array $userAgentBlockList = [];
    private array $countryAllowList = [];
    private array $countryBlockList = [];
    private array $ipAllowList = [];
    private array $ipBlockList = [];

    private LoggerInterface $logger;

    public function __construct(Config $config, LoggerInterface $logger)
    {
        $this->logger = $logger;

        $antiSpamConfig = $config->offsetGet('anti_spam');

        if (isset($antiSpamConfig['user_agent_allowed']) && $antiSpamConfig['user_agent_allowed']) {
            $this->userAgentAllowList = $antiSpamConfig['user_agent_allowed'];
        }
        if (isset($antiSpamConfig['user_agent_blocked']) && $antiSpamConfig['user_agent_blocked']) {
            $this->userAgentBlockList = $antiSpamConfig['user_agent_blocked'];
        }

        if (isset($antiSpamConfig['country_allowed']) && $antiSpamConfig['country_allowed']) {
            $this->countryAllowList = $antiSpamConfig['country_allowed'];
        }
        if (isset($antiSpamConfig['country_blocked']) && $antiSpamConfig['country_blocked']) {
            $this->countryBlockList = $antiSpamConfig['country_blocked'];
        }

        if (isset($antiSpamConfig['geoip_database']) && $antiSpamConfig['geoip_database']) {
            $this->geoIpDatabase = $antiSpamConfig['geoip_database'];
        }
        $this->geoIpReader = new Reader($this->geoIpDatabase);

        if (isset($antiSpamConfig['ip_allowed']) && $antiSpamConfig['ip_allowed']) {
            $this->ipAllowList = $antiSpamConfig['ip_allowed'];
        }
        if (isset($antiSpamConfig['ip_blocked']) && $antiSpamConfig['ip_blocked']) {
            $this->ipBlockList = $antiSpamConfig['ip_blocked'];
        }
    }

    public function handle(Saving $event)
    {
        $score = 0;

        if (!$event->user->exists) {
            $userIp = $_SERVER['REMOTE_ADDR'];
            if ($userIp) {
                $country = $this->getCountry($userIp);
                if ($country) {
                    if ($this->isCountryBlocked($country)) {
                        $score--;
                    }
                    if ($this->isCountryAllowed($country)) {
                        $score++;
                    }
                }

                if ($this->isIpBlocked($userIp)) {
                    $score--;
                }
                if ($this->isIpAllowed($userIp)) {
                    $score++;
                }
            }

            $userAgent = $this->getUserAgent();
            if ($userAgent) {
                if ($this->isUserAgentBlocked($userAgent)) {
                    $score--;
                }
                if ($this->isUserAgentAllowed($userAgent)) {
                    $score++;
                }
            }

            if ($score < 1) {
                $this->logger->alert(
                    sprintf('Anti-Spam: Blocked user agent "%s" from %s with score %d', $userAgent, $country, $score)
                );
                throw new ValidationException([sprintf('Anti-Spam protection')]);
            }
        }
    }

    private function getCountry(string $ip): ?string
    {
        try {
            $response = $this->geoIpReader->get($ip);
            if (isset($response['country']['iso_code'])) {
                return $response['country']['iso_code'];
            }
        } catch (\Exception $e) {
        }

        return null;
    }

    private function isCountryBlocked(string $country): bool
    {
        return in_array($country, $this->countryBlockList);
    }

    private function isCountryAllowed(string $country): bool
    {
        return in_array($country, $this->countryAllowList);
    }

    private function getUserAgent(): ?string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? null;
    }

    private function isUserAgentBlocked(string $userAgent): bool
    {
        foreach ($this->userAgentBlockList as $subString) {
            if (stripos($userAgent, $subString) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isUserAgentAllowed(string $userAgent): bool
    {
        foreach ($this->userAgentAllowList as $subString) {
            if (stripos($userAgent, $subString) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isIpBlocked(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->ipBlockList);
    }

    private function isIpAllowed(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->ipAllowList);
    }
}
