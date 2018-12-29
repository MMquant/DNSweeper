# DNS Resolvers believed to return correct and uncensored answers
# Every resolver here is manually tested
# Trusted resolvers are used for fine filtering

TRUSTED_RESOLVERS = [

    '8.8.8.8', '8.8.4.4',                   # Google
    '208.67.222.222', '208.67.220.220',     # OpenDNS
    '1.1.1.1', '1.0.0.1',                   # CloudFlare
    '9.9.9.9', '149.112.112.112',           # Quad9
    '64.6.64.6', '64.6.65.6',               # Verisign
    '84.200.69.80', '84.200.70.40',         # DNS.WATCH
    '8.26.56.26', '8.20.247.20',            # Comodo Secure DNS
    '195.46.39.39', '195.46.39.40',         # SafeDNS
    '216.146.35.35', '216.146.36.36',       # Dyn
    '37.235.1.174', '37.235.1.177',         # FreeDNS
    '77.88.8.8', '77.88.8.1',               # Yandex.DNS
    '91.239.100.100', '89.233.43.71'        # UncensoredDNS

]