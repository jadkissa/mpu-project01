-- rules
ips = {
    include = '/etc/snort/rules/local.rules',
    variables = {
        nets = {
            HOME_NET = '172.20.10.0/28',
            EXTERNAL_NET = '!$HOME_NET',
        },
        ports = {
            HTTP_PORTS = '8080',
        }
    }
}

-- detection engine
detection = {
    hyperscan_literals = false,
}

-- logging
alert_json = {
    file = true,
    limit = 10,
    fields = 'timestamp src_addr dst_addr src_port dst_port proto gid sid rev msg priority class',
}

http_inspect = {}