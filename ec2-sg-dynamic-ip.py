import boto.ec2
import urllib2
import optparse

def get_my_ip():
    my_ip = urllib2.urlopen("http://api.ipify.org").read()
    return my_ip

def add_sg_rule(conn, security_group_id, my_ip):
    sg = conn.get_all_security_groups(group_ids=security_group_id)[0]
    sg.authorize(ip_protocol="tcp", from_port=22, to_port=22, cidr_ip=my_ip + "/32", src_group=None, dry_run=False)

def remove_sg_rule(conn, security_group_id, my_ip):
    sg = conn.get_all_security_groups(group_ids=security_group_id)[0]
    sg.revoke('tcp', 22, 22, cidr_ip=my_ip + "/32")

def main():
    parser = optparse.OptionParser()
    parser.add_option('-a','--action',help='Add or delete rule in Security Group', dest='action', choices=['add', 'remove',])
    parser.add_option('-k', '--key', help='Amazon Access key', dest='aws_access_key_id')
    parser.add_option('-s', '--secret', help='Amazon Secret Key', dest='aws_secret_access_key')
    parser.add_option('-g', '--group', help='Amazon Security Group', dest='security_group_id')
    (opts, args) = parser.parse_args()
    action = opts.action
    aws_access_key_id = opts.aws_access_key_id
    aws_secret_access_key = opts.aws_secret_access_key
    security_group_id = opts.security_group_id

    conn = boto.ec2.connect_to_region("us-east-1", aws_access_key_id=opts.aws_access_key_id, aws_secret_access_key=opts.aws_secret_access_key)
    my_ip = get_my_ip()
    if action == 'add':
        add_sg_rule(conn, security_group_id, my_ip)
    if action == 'remove':
        remove_sg_rule(conn, security_group_id, my_ip)

if __name__ == "__main__":
    main()
