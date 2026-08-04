<?php

namespace QUI\OAuth;

final class DynamicResourceTrustPolicy
{
    public static function validate(string $resource, string $issuer): string
    {
        $resource = ClientConfiguration::validateResources([$resource])[0];
        $issuer = ClientConfiguration::validateResources([$issuer])[0];

        if (
            ClientConfiguration::hasSameOrigin($resource, $issuer)
            || in_array(
                self::getOrigin($resource),
                self::getTrustedVhostOrigins(),
                true
            )
        ) {
            return $resource;
        }

        throw new \InvalidArgumentException(
            'Dynamically registered clients may only use same-origin resources or configured VHost domains.'
        );
    }

    /**
     * @return list<string>
     */
    public static function getTrustedVhostOrigins(): array
    {
        $origins = [];

        foreach (\QUI::vhosts() as $host => $data) {
            if (
                !is_string($host)
                || !is_array($data)
                || empty($data['project'])
            ) {
                continue;
            }

            self::addVhostOrigin($origins, $host);

            foreach ($data as $key => $value) {
                if (
                    $key !== 'httpshost'
                    && (
                        !is_string($key)
                        || preg_match('/^[a-z]{2}$/i', $key) !== 1
                    )
                ) {
                    continue;
                }

                if (is_string($value)) {
                    self::addVhostOrigin($origins, $value);
                }
            }
        }

        $origins = array_keys($origins);
        sort($origins);

        return $origins;
    }

    /**
     * @param array<string, true> $origins
     */
    private static function addVhostOrigin(array &$origins, string $host): void
    {
        $host = trim($host);

        if ($host === '' || str_contains($host, '*')) {
            return;
        }

        $url = str_contains($host, '://') ? $host : 'https://' . $host;
        $parts = parse_url($url);

        if (
            !is_array($parts)
            || strtolower((string)($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || (isset($parts['path']) && !in_array($parts['path'], ['', '/'], true))
        ) {
            return;
        }

        $origin = 'https://' . strtolower((string)$parts['host']);
        $port = $parts['port'] ?? 443;

        if ($port !== 443) {
            $origin .= ':' . $port;
        }

        $origins[$origin] = true;
    }

    private static function getOrigin(string $resource): string
    {
        $parts = parse_url($resource);

        if (
            !is_array($parts)
            || !isset($parts['scheme'], $parts['host'])
        ) {
            throw new \InvalidArgumentException(
                'The OAuth resource URI is invalid.'
            );
        }

        $origin = strtolower((string)$parts['scheme'])
            . '://'
            . strtolower((string)$parts['host']);
        $port = $parts['port'] ?? 443;

        if ($port !== 443) {
            $origin .= ':' . $port;
        }

        return $origin;
    }
}
