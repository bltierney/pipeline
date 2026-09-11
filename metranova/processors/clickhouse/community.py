import logging
import os
import ipaddress
from metranova.processors.clickhouse.base import BaseMetadataProcessor

logger = logging.getLogger(__name__)

class CommunityRegistryProcessor(BaseMetadataProcessor):
    def __init__(self, pipeline):
        super().__init__(pipeline)
        self.logger = logger
        self.table = os.getenv('CLICKHOUSE_COMMUNITY_METADATA_TABLE', 'meta_ip_community')
        self.val_id_field = ['community_id']
        self.column_defs.extend([
            ['ip_subnet', 'Array(Tuple(IPv6,UInt8))', True],
            ['organization_name', 'Nullable(String)', True],
            ['community', 'LowCardinality(Nullable(String))', True],
            ['asn', 'Nullable(UInt32)', True],
            ['notes', 'Nullable(String)', True]
        ])
        self.required_fields = [
            ["community_id"],
            ["addresses"]
        ]

    def match_message(self, value):
        #override base since don't set table in url
        return self.has_match_field(value)

    def build_metadata_fields(self, value: dict) -> dict | None:
        #iterate over strings in value['addresses'] and build a new list of tuples where first element is IP address and second is prefix length.
        ip_subnets = []
        for addr in value['addresses']:
            #every address must include a '/' prefix length; anything else is an error
            if '/' not in addr:
                self.logger.warning(f"Missing prefix length (no '/'): {addr}")
                continue
            ip, prefix_str = addr.split('/', 1)
            try:
                prefix = int(prefix_str)
            except ValueError:
                self.logger.warning(f"Invalid IP address format: {addr}")
                continue

            ip_subnets.append((ip, prefix))

            #subnets smaller than /24 (IPv4) or /64 (IPv6) are often the result of
            #de-identification elsewhere, where the host portion of the address is
            #replaced with the value 1 (e.g. .1 for IPv4, ::1 for IPv6). Add that
            #address too so we can still match against data anonymized that way.
            try:
                version = ipaddress.ip_address(ip).version
            except ValueError:
                self.logger.warning(f"Invalid IP address format: {addr}")
                continue
            boundary_prefix = 24 if version == 4 else 64
            host_prefix = 32 if version == 4 else 128
            if prefix > boundary_prefix:
                network = ipaddress.ip_network(f"{ip}/{boundary_prefix}", strict=False)
                deidentified_ip = network.network_address + 1
                ip_subnets.append((str(deidentified_ip), host_prefix))

        #de-duplicate while preserving order (multiple narrow subnets can share
        #the same enclosing /24 or /64, which would otherwise generate the same
        #de-identified address more than once)
        ip_subnets = list(dict.fromkeys(ip_subnets))

        #init record
        formatted_record = {
            'ip_subnet': ip_subnets,
            'organization_name': value.get('org_name', None),
            'community': value.get('community', None),
            'asn': value.get('asn', None),
            'notes': value.get('notes', None),
            'ext': '{}',
            'tag': []
        }

        #cast asn to an int, and set to None if exception when casting
        if formatted_record['asn'] is not None:
            try:
                formatted_record['asn'] = int(formatted_record['asn'])
            except ValueError:
                formatted_record['asn'] = None

        return formatted_record

