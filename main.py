from boto3 import client
from botocore.exceptions import  *
import requests
import json
import os
import logging
from datetime import datetime
import time

#Variables
regions = "eu-west-1"
account = "553885614755"
# lb_name = ["cloudfront-ip-change-lab"]
lb_name = ["cloudfront-ip-change-lab"]
ec2 = client('ec2')
alb = client('elbv2')


# logger = logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)


with open(os.path.join(os.path.dirname(__file__), "ip-space-changed.json"), mode='r') as file:
    sns_message = json.loads(json.load(file)["Records"][0]["Sns"]["Message"])
    print(type(sns_message))
    print(sns_message)

def read_ip_space_changed(SnsMessage):
    """
    :param sns_message: take the input of ["Records"][0]["Sns"]["Message"] from SNS notification
    :type sns_message: dict
    :return: response of the URL(deserialized)
    :rtype: dict
    """
    resp = requests.get(SnsMessage["url"])
    # json.loads(resp.text))
    return json.loads(resp.text)

def filter_cloudfront_service_ip_range(resp_ip_object):
    """
    :param resp_ip_object: represents the aws public IP cidr range
    :type resp_ip_object: dict
    :return: CloudfrontCidrRange: array of CIDR range for CloudFront
    :rtype: list
    """
    # Filters only IPV4 address from the file
    # print("A",resp_ip_object)
    CloudfrontCidrRange = [ i["ip_prefix"] for i in resp_ip_object["prefixes"] if i["service"] == "CLOUDFRONT"]
    # print(CloudfrontCidrRange)
    return CloudfrontCidrRange

def create_sg(sg_group_name,sg_description,vpc_id):
    """
    :param sg_group_name: The name of the security group
    :type sg_group_name: str
    :param sg_description: A description for the security group
    :type sg_description:  str
    :param vpc_id : VPC ID for the SG creation
    :type vpc_id: str
    :return: security group id
    """
    try:
        response = ec2.create_security_group(GroupName=sg_group_name,Description=sg_description,VpcId=vpc_id)
        security_group_id = response['GroupId']
        return security_group_id
        # ingress_rule = [{'IpProtocol': 'http',} for for ip in cloudfront_cidr_range]
    except ClientError as err:
        logging.warning("Error creating security group: %s", err)
        raise err


def add_sg_ingress_rule(sg_id,ip_permissions):
    """
    :param sg_id: Security Group ID on which to add ingress rule.
    :type sg_id: string
    :param ip_permissions: list of inbound ip permissions.
    :type ip_permissions: list
    :return:
    """
    # print(sg_id,ip_permissions)
    try:
        response = ec2.authorize_security_group_ingress(GroupId=sg_id,IpPermissions=ip_permissions)
        logging.info(response)
        print("a",response)
    except ClientError as err:
        # print (err)
        logging.warning("Error creating ingress rule: %s", err)
        raise err


def execute_sg_workflow(cloudfront_cidr_range,vpc_id,ports=[80,443], no_of_rules=99):
    """
    :param cloudfront_cidr_range: array of public Ip range
    :type cloudfront_cidr_range: list
    :param vpc_id: The VPC id on which the SG will be created.
    :type vpc_id: str
    :param ports: inbound network ports from CloudFront to LoadBalancer.
    :type ports: list
    :param no_of_rules: number of inbound rules per SG
    :return:
    """
    print(cloudfront_cidr_range)
    new_sg = []
    sliced_ip_arr = [cloudfront_cidr_range[i:i+no_of_rules] for i in range(0,len(cloudfront_cidr_range),no_of_rules)]
    print(sliced_ip_arr)
    now = datetime.now()
    for port in ports:
        # print("immediate Brake")
        for index,arr in enumerate(sliced_ip_arr):
            ingress_rule = [{'IpProtocol': 'tcp','FromPort': port, 'ToPort': port, "IpRanges": [{"CidrIp": ip }] } for ip in arr]
            try:
                sg_id = create_sg(sg_description="allow inbound CF only",sg_group_name="ingress_only_from_cf_"+str(port)+"-"+str(index)+"-"+now.strftime("%Y-%m-%d-%H-%M-%S") ,vpc_id=vpc_id)
                print(type(sg_id))
                add_sg_ingress_rule(sg_id, ingress_rule)
                if sg_id is not None:
                    new_sg.append(sg_id)
            except Exception as err:
                logging.error("execution failed:%s", err)
                break
    print(new_sg)
    return new_sg

def fetch_lb_sg(lb_name=[]):
    """
    :param lb_name: name of the loadbalancer to query for attached SG
    :return:
    """
    try:
        response = alb.describe_load_balancers(Names=lb_name)
        sg = response["LoadBalancers"][0]["SecurityGroups"]
        lb_arn = response["LoadBalancers"][0]["LoadBalancerArn"]
        # print(lb_arn,sg)
        return lb_arn, sg
    except alb.exceptions.LoadBalancerNotFoundException as err:
        logging.warning("Please provide valid LB name which exist in current region : {0}".format(err.response['Error']['Message']))
    except Exception as err:
        logging.error(err.response['Error']['Message'])
        raise err

def associate_new_sg_to_lb(lb_arn,sg_ids=[]):
    """
    :param lb_arn: ARN of Loadbalancer
    :param sg_ids: list of SG that need to be attached to LB
    :return:
    """
    try:
        print(lb_arn,sg_ids)
        response = alb.set_security_groups(LoadBalancerArn=lb_arn,SecurityGroups=sg_ids)
        logging.info(response)
    except alb.exceptions.LoadBalancerNotFoundException as err:
        logging.warning("Please provide valid LB name which exist in current region : {0}".format(err.response['Error']['Message']))
    except Exception as err:
        logging.error(err.response['Error']['Message'])
        raise err

def cleanup_old_sg(sg_id=[]):
    """
    Delete the SG in the current region.
    :param sg_id: array of security groups to delete
    :return: None
    """
    for sg in sg_id:
        time.sleep(30)
        try:
            response = ec2.delete_security_group(GroupId=sg)
            logging.info(response)
        except Exception as err:
            logging.error(err.response['Error']['Message'])
            print("SG deletion failed.Please cleanup the {0} manually.".format(sg))


if __name__ == "__main__":
    new_sg=execute_sg_workflow(filter_cloudfront_service_ip_range(read_ip_space_changed(sns_message)),"vpc-fef0de98")
    lb_arn, current_sg = fetch_lb_sg(lb_name)
    associate_new_sg_to_lb(lb_arn,new_sg)
    cleanup_old_sg(current_sg)
