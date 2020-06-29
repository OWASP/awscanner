import argparse
import sys
import textwrap

import boto3
from botocore.exceptions import ClientError
from loguru import logger

from __version__ import _version

DEBUG = True

logger.remove()
if DEBUG:
    logger.add(sys.stderr, level="DEBUG")
else:
    logger.add(sys.stderr, level="INFO")


def scan_ec2(region, sec_groups):
        ec2 = boto3.resource('ec2', region_name=region)

        machines = []

        logger.debug('Analysing ec2 machines')
        for instance in ec2.instances.all():
            friendly_name = 'Unknown'
            for t in instance.tags:
                if t['Key'] == 'Name':
                    friendly_name = t['Value']

            exposed_ports = []
            for g in instance.security_groups:
                rules_with_pub_access = list(filter(
                    lambda group: group['GroupName'] == g['GroupName'] and group['has_pub_access']
                    , sec_groups))
                if len(rules_with_pub_access) > 0:
                    for exposed_group in rules_with_pub_access:
                        perms = exposed_group['IpPermissions']
                        for p in perms:
                            try:
                                port = p["FromPort"]
                                if port == 0:
                                    port = 'any'
                                port_string = f'{port}/{p["IpProtocol"]}'
                            except:
                                protocol = p["IpProtocol"]
                                if protocol == '-1':
                                    protocol = 'any'

                                port_string = f'any/{protocol}'

                            exposed_ports.append(port_string)

            detected = {
                'type': 'ec2',
                'id' : instance.id,
                'name': friendly_name,
                'IP': instance.public_ip_address,
                'DNS': instance.public_dns_name,
                'exposed_ports': exposed_ports,
                'is_exposed': True if len(rules_with_pub_access) > 0 else False
            }
            logger.debug(detected)
            machines.append(detected)

        return machines


def get_security_groups(region):
    ec2_client = boto3.client('ec2', region_name=region)
    sec_groups = ec2_client.describe_security_groups()['SecurityGroups']
    logger.warning('Analysing security group for public access ')
    for key, g in enumerate(sec_groups):
        try:
            sec_groups[key]['has_pub_access'] = False
            for permissions in g['IpPermissions']:
                for ip_range in permissions['IpRanges']:
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        sec_groups[key]['has_pub_access'] = True
                        logger.warning(f'Group {sec_groups[key]["GroupName"]} - HAS public access')
                        logger.warning(f'Group Description: {sec_groups[key]["Description"]}')
                    else:
                        logger.debug(f'Group {sec_groups[key]["GroupName"]} - No public access')
        except TypeError:
            continue
    logger.debug(sec_groups)
    return sec_groups


def scan_rds(region, sec_groups):
    rds_nodes = []
    logger.debug('Scanning RDS')
    rds = boto3.client('rds', region_name=region)
    rds_instances = rds.describe_db_instances()
    for instance in rds_instances['DBInstances']:
        for g in sec_groups:
            if g['GroupId'] == instance['VpcSecurityGroups'][0]['VpcSecurityGroupId']:

                detected = {
                    'type': 'rds',
                    'id': instance['DbiResourceId'],
                    'name': instance['DBInstanceIdentifier'],
                    'DNS': instance['Endpoint']['Address'],
                    'exposed_ports': instance['Endpoint']['Port'],
                    'is_exposed': g['has_pub_access']
                }

                logger.debug(detected)
                rds_nodes.append(detected)
    return rds_nodes


def scan_elb(region, machines):

    elbList = boto3.client('elb', region_name=region)
    load_balancers = elbList.describe_load_balancers()

    for elb in load_balancers['LoadBalancerDescriptions']:
        for ec2Id in elb['Instances']:
            for m in machines:
                if m['id'] == ec2Id['InstanceId']:
                    m['DNS'] = elb['DNSName']
                    logger.debug(f'Adding DNS name to machine {m["id"]} : {elb["DNSName"]} ')


def scan_all(regions):


    for region in regions:
        logger.info('\n----------------')
        logger.info(f'Scanning {region}')
        try:
            sec_groups = get_security_groups(region)
            machines = scan_ec2(region,sec_groups)

            logger.info(f'found EC2 machines {len(machines)}')
            scan_elb(region, machines)
            scan_rds(region, sec_groups)

        except ClientError as ce:
            logger.error(f'error accessing ec2 on [{region}]')
            logger.debug(ce.response['Error']['Code'])
            logger.debug(ce.response['Error']['Message'])


if __name__ == '__main__':

    with open('regions.csv', 'r') as reg_file:
        aws_regions = {r.split('\t')[1][:-1]: r.split('\t')[0] for r in reg_file}
    logger.debug('loaded AWS regions')


    parser = argparse.ArgumentParser(
         usage='%(prog)s [options]',
         formatter_class=argparse.RawDescriptionHelpFormatter,
         description=textwrap.dedent('''\
         Common Usages
         --------------------------------
             %(prog)s 
        '''))

    parser.add_argument('--version', action='version', version='%(prog)s ' + _version)
    parser.add_argument('--action', type=str, action='store', help='Working mode: show-event show-stats show-dates',
                        choices=['scan-all', 'print-regions'],
                        default='scan-all')
    parser.add_argument('--region', type=str, action='store', choices=aws_regions.keys(), default='')

    results = parser.parse_args()

    # prepare
    region_to_scan = []
    if results.region == '':
        region_to_scan = aws_regions.keys()
    else:
        region_to_scan.append(results.region)

    # action

    if results.action == 'scan-all':
        scan_all(region_to_scan)

    if results.action == 'print-regions':
        for k in aws_regions.keys():
            print(k)
