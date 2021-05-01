This extension is specific to [forum.archlinux.de](https://forum.archlinux.de/). You might find its code useful to
implement your own solution.

Optional configuration:

    'anti_spam' => [
        'user_agent_allowed' => ['BSD'],
        'user_agent_blocked' => ['DOS', 'Windows'],
        'geoip_database' => '/opt/GeoLite2-Country.mmdb'
        'country_allowed' => ['FR', 'NL'],
        'country_blocked' => ['DE'],
        'ip_allowed' => ['10.0.0.0/8', '::1'],
        'ip_blocked' => ['192.168.0.0/16'],
    ]
