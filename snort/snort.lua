-- /home/jad/Desktop/mpu01/snort/snort.lua

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

-- rules
ips = {
    include = '/etc/snort/rules/local.rules',
}