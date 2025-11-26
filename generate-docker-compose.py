import yaml

# Hardcoded network definitions: list of (subnet, client count, interval)
RANGES = [
    ('172.16.1.0/24', 4, 0.1),
    ('172.16.2.0/24', 2, 0.1),
    ('172.16.3.0/24', 5, 0.1),
    ('172.16.16.0/24', 33, 0.07),
]

# Build contexts and Dockerfile names for services
PROXY_BUILD    = {'context': './proxy',    'dockerfile': 'Dockerfile'}
CLIENT_BUILD   = {'context': './client',   'dockerfile': 'Dockerfile'}
FILEBEAT_BUILD = {'context': './filebeat', 'dockerfile': 'Dockerfile'}
CIDRX_BUILD    = {'context': './cidrx',    'dockerfile': 'Dockerfile'}

TARGET_URL  = 'http://proxy:80/'
OUTPUT_FILE = 'docker-compose.yml'


def generate_compose():
    services = {}
    networks = {}
    volumes  = {
        'filebeat_data': {},
    }

    # ── proxy ──
    proxy_nets = {f'net{i+1}': {} for i in range(len(RANGES))}
    services['proxy'] = {
        'build':          PROXY_BUILD,
        'container_name': 'proxy',
        'restart':        'unless-stopped',
        'ports':          ['80'],
        'volumes':        [
            '/tmp:/var/log/nginx:rw',
        ],
        'networks':       proxy_nets,
    }

    # ── cidrx ──
    services['cidrx'] = {
        'build':          CIDRX_BUILD,
        'container_name': 'cidrx',
        'restart':        'unless-stopped',
        'ports':          ['9000:9000'],
        'networks':       proxy_nets,
    }

    # ── filebeat ──
    services['filebeat'] = {
        'build':          FILEBEAT_BUILD,
        'container_name': 'filebeat',
        'user':           'root',
        'depends_on':     ['proxy', 'cidrx'],
        'restart':        'unless-stopped',
        'networks':       proxy_nets,
        'volumes': [
            '/tmp:/var/log/nginx:ro',
            'filebeat_data:/usr/share/filebeat/data',
        ],
        'environment': {
            'INGESTOR_HOST':       'cidrx:9000',
            'PROXY_CONTAINER_NAME': 'proxy',
        },
    }

    # ── clients ──
    for i, (subnet, count, interval) in enumerate(RANGES):
        net_name = f'net{i+1}'
        networks[net_name] = {
            'driver': 'bridge',
            'ipam': {
                'driver': 'default',
                'config': [{'subnet': subnet}],
            }
        }
        base = subnet.rsplit('.', 1)[0]

        for j in range(1, count+1):
            name = f'client{i+1}_{j}'
            services[name] = {
                'build':          CLIENT_BUILD,
                'container_name': name,
                'depends_on':     ['proxy'],
                'networks':       {net_name: {'ipv4_address': f"{base}.{31+j}"}},
                'environment': {
                    'TARGET_URL': TARGET_URL,
                    'INTERVAL':   interval,
                }
            }

    compose = {
        'services': services,
        'networks': networks,
        'volumes':  volumes,
    }

    with open(OUTPUT_FILE, 'w') as f:
        yaml.dump(compose, f, sort_keys=False)
    print(f"Generated {OUTPUT_FILE} with {len(services) - 3} clients on {len(networks)} networks.")


if __name__ == '__main__':
    generate_compose()
