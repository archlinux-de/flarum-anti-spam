<?php

namespace ArchLinux\AntiSpam\Validator;

use Flarum\Foundation\Config;
use Flarum\Foundation\ValidationException;
use Flarum\User\Event\Saving;
use Illuminate\Support\Arr;
use MaxMind\Db\Reader;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;

class RegistrationHandler
{
    private Reader $geoIpReader;

    /** @var string[] */
    private array $userAgentAllowList;

    /** @var string[] */
    private array $userAgentBlockList;

    /** @var string[] */
    private array $countryAllowList;

    /** @var string[] */
    private array $countryBlockList;

    /** @var string[] */
    private array $ipAllowList;

    /** @var string[] */
    private array $ipBlockList;

    private bool $debug;

    public function __construct(
        private Config $config,
        private LoggerInterface $logger,
        GeoIpReaderFactory $geoIpReaderFactory
    ) {
        $antiSpamConfig = $this->getAntiSpamConfig();

        $this->userAgentAllowList = $this->getStringArray($antiSpamConfig, 'user_agent_allowed');
        $this->userAgentBlockList = $this->getStringArray($antiSpamConfig, 'user_agent_blocked');

        $this->countryAllowList = $this->getStringArray($antiSpamConfig, 'country_allowed');
        $this->countryBlockList = $this->getStringArray($antiSpamConfig, 'country_blocked');

        $this->ipAllowList = $this->getStringArray(
            $antiSpamConfig,
            'ip_allowed',
            ['10.0.0.0/8', '127.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '::1/128']
        );
        $this->ipBlockList = $this->getStringArray($antiSpamConfig, 'ip_blocked');

        $this->debug = (bool)Arr::get($antiSpamConfig, 'debug', $config->inDebugMode());

        $this->geoIpReader = $geoIpReaderFactory->createReader();
    }

    /**
     * @return string[]|\ArrayAccess<string,string>
     */
    private function getAntiSpamConfig(): array|\ArrayAccess
    {
        $antiSpamConfig = $this->config->offsetGet('anti_spam') ?? [];
        assert(is_array($antiSpamConfig) || $antiSpamConfig instanceof \ArrayAccess);
        return $antiSpamConfig;
    }

    /**
     * @param string[]|\ArrayAccess<string,string> $array
     * @param string $key
     * @param string[] $default
     * @return string[]
     */
    private function getStringArray(array|\ArrayAccess $array, string $key, array $default = []): array
    {
        $value = Arr::get($array, $key, $default);
        assert(is_array($value));
        return $value;
    }

    public function handle(Saving $event): void
    {
        $score = 0;

        if (!$event->user->exists) {
            $userIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
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

            $logContext = [
                'username' => $event->user->username,
                'email' => $event->user->email,
                'ip' => $userIp ?? '-',
                'country' => $country ?? '-',
                'agent' => $userAgent ?? '-',
                'score' => $score
            ];

            if ($score < 1) {
                $this->logger->info('Anti-Spam blocked user registration', $logContext);
                throw new ValidationException(
                    ['anti-spam-message' => 'Registration blocked by Anti-Spam.'],
                    ['anti-spam-score' => sprintf('Anti-Spam score: %d', $score)]
                );
            } elseif ($this->debug) {
                $this->logger->debug('Anti-Spam debug', $logContext);
            }
        }
    }

    private function getCountry(string $ip): ?string
    {
        try {
            $response = $this->geoIpReader->get($ip);
            if (is_array($response) && isset($response['country']) && isset($response['country']['iso_code'])) {
                return $response['country']['iso_code'];
            }
        } catch (\Exception $e) {
            $this->logger->error($e->getMessage());
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

    private function isIpBlocked(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->ipBlockList);
    }

    private function isIpAllowed(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->ipAllowList);
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
}
