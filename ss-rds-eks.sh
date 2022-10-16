#!/bin/sh

function print_line()
{
    echo "---------------------------------"
}

function install_packages()
{
    current_dir=`pwd`
    sudo yum install -y jq  > ${TERM1} 2>&1
    print_line
    echo "Installing aws cli v2"
    print_line
    aws --version | grep aws-cli\/2 > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
        cd $current_dir
	return
    fi
    cd /tmp
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" > ${TERM1} 2>&1
    unzip -o awscliv2.zip > ${TERM1} 2>&1
    sudo ./aws/install --update > ${TERM1} 2>&1
    cd $current_dir
}

function install_k8s_utilities()
{
    print_line
    echo "Installing Kubectl"
    print_line
    sudo curl -o /usr/local/bin/kubectl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"  > ${TERM1} 2>&1
    sudo chmod +x /usr/local/bin/kubectl > ${TERM1} 2>&1
    print_line
    echo "Installing eksctl"
    print_line
    curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp > ${TERM1} 2>&1
    sudo mv /tmp/eksctl /usr/local/bin
    sudo chmod +x /usr/local/bin/eksctl
    print_line
    echo "Installing helm"
    print_line
    curl -s https://fluxcd.io/install.sh | sudo bash > ${TERM1} 2>&1
    curl -sSL https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash > ${TERM1} 2>&1

}

function install_postgresql()
{
    print_line
    echo "Installing Postgresql client"
    print_line
    sudo amazon-linux-extras install -y postgresql14 > ${TERM1} 2>&1
}


function update_kubeconfig()
{
    print_line
    echo "Updating kubeconfig"
    print_line
    aws eks update-kubeconfig --name ${EKS_CLUSTER_NAME}
}


function update_eks()
{
    print_line
    echo "Enabling clusters to use iam oidc"
    print_line
    eksctl utils associate-iam-oidc-provider --cluster ${EKS_CLUSTER_NAME} --region ${AWS_REGION} --approve
}


function chk_installation()
{ 
    print_line
    echo "Checking the current installation"
    print_line
    for command in kubectl aws eksctl flux helm jq
    do
        which $command &>${TERM1} && echo "$command present" || echo "$command NOT FOUND"
    done

}

function install_loadbalancer()
{
    print_line
    echo "Installing load balancer"
    print_line

    eksctl utils associate-iam-oidc-provider --region ${AWS_REGION} --cluster ${EKS_CLUSTER_NAME} --approve

    curl -o iam_policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.2.0/docs/install/iam_policy.json

    aws iam create-policy --policy-name AWSLoadBalancerControllerIAMPolicy --policy-document file://iam_policy.json

    eksctl create iamserviceaccount \
     --cluster=${EKS_CLUSTER_NAME} \
     --namespace=${EKS_NAMESPACE} \
     --name=aws-load-balancer-controller \
     --attach-policy-arn=arn:aws:iam::${AWS_ACCOUNT_ID}:policy/AWSLoadBalancerControllerIAMPolicy \
     --override-existing-serviceaccounts \
     --approve

    kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller//crds?ref=master"
    helm repo add eks https://aws.github.io/eks-charts

    helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
     --set clusterName=${EKS_CLUSTER_NAME} \
     --set serviceAccount.create=false \
     --set region=${AWS_REGION} \
     --set vpcId=${VPCID} \
     --set serviceAccount.name=aws-load-balancer-controller \
     -n ${EKS_NAMESPACE}

}


function chk_aws_environment()
{
    print_line
    echo "Checking AWS environment"
    print_line
    for myenv in "${AWS_DEFAULT_REGION}" "${AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY}" "${AWS_SESSION_TOKEN}"
    do
        if [ x"${myenv}" == "x" ] ; then
            echo "AWS environment is missing. Please import from event engine"
	    exit
	fi
    done
    echo "AWS environment exists"
    
}


function run_kubectl()
{
    print_line
    echo "kubectl get nodes -o wide"
    print_line
    kubectl get nodes -o wide
    print_line
    echo "kubectl get pods --all-namespaces"
    print_line
    kubectl get pods --all-namespaces
}


function chk_cloud9_permission()
{
    aws sts get-caller-identity | grep ${INSTANCE_ROLE}  
    if [ $? -ne 0 ] ; then
	echo "Fixing the cloud9 permission"
        environment_id=`aws ec2 describe-instances --instance-id $(curl -s http://169.254.169.254/latest/meta-data/instance-id) --query "Reservations[*].Instances[*].Tags[?Key=='aws:cloud9:environment'].Value" --output text`
        aws cloud9 update-environment --environment-id ${environment_id} --region ${AWS_REGION} --managed-credentials-action DISABLE
	sleep 10
        ls -l $HOME/.aws/credentials > /dev/null 2>&1
        if [ $? -eq 0 ] ; then
             echo "!!! Credentials file exists"
        else
            echo "Credentials file does not exists"
        fi
	echo "After fixing the credentials. Current role"
        aws sts get-caller-identity | grep ${INSTANCE_ROLE}
    fi
}


function print_environment()
{
    print_line
    echo "Current Region : ${AWS_REGION}"
    echo "EKS Namespace  : ${EKS_NAMESPACE}"
    echo "EKS Cluster Name : ${EKS_CLUSTER_NAME}"
    echo "VPCID           : ${VPCID}"
    echo "Subnet A        : ${SUBNETA}"
    echo "Subnet B        : ${SUBNETB}"
    echo "Subnet C        : ${SUBNETC}"
    echo "VPC SG           : ${vpcsg}"
    print_line
}

function create_eks_cluster()
{
    typeset -i counter
    counter=0
    echo "aws cloudformation  create-stack --stack-name ${EKS_STACK_NAME} --parameters ParameterKey=VPC,ParameterValue=${VPCID} ParameterKey=SubnetAPrivate,ParameterValue=${SUBNETA} ParameterKey=SubnetBPrivate,ParameterValue=${SUBNETB} ParameterKey=SubnetCPrivate,ParameterValue=${SUBNETC} --template-body file://${EKS_CFN_FILE} --capabilities CAPABILITY_IAM"
    aws cloudformation  create-stack --stack-name ${EKS_STACK_NAME} --parameters ParameterKey=VPC,ParameterValue=${VPCID} ParameterKey=SubnetAPrivate,ParameterValue=${SUBNETA} ParameterKey=SubnetBPrivate,ParameterValue=${SUBNETB} ParameterKey=SubnetCPrivate,ParameterValue=${SUBNETC} --template-body file://${EKS_CFN_FILE} --capabilities CAPABILITY_IAM
    sleep 60
    # Checking to make sure the cloudformation completes before continuing
    while  [ $counter -lt 100 ]
    do
        STATUS=`aws cloudformation describe-stacks --stack-name ${EKS_STACK_NAME} --query  Stacks[0].StackStatus`
	echo ${STATUS} |  grep CREATE_IN_PROGRESS  > /dev/null 
	if [ $? -eq 0 ] ; then
	    echo "EKS cluster Stack creation is in progress ${STATUS}... waiting"
	    sleep 60
	else
	    echo "EKS cluster Stack creation status is ${STATUS} breaking the loop"
	    break
	fi
    done
    echo ${STATUS} |  grep CREATE_COMPLETE  > /dev/null 
    if [ $? -eq 0 ] ; then
       echo "EKS cluster Stack creation completed successfully"
    else
       echo "EKS cluster Stack creation failed with status ${STATUS}.. exiting"
       exit 1 
    fi
}

function generate_sql()
{
   pwd
   echo "Generating SQL file to be applied to shardingsphere" 
   username=$(aws secretsmanager get-secret-value --secret-id ${RDSSECRETARN}| jq -r .SecretString | jq -r .username)
   password=$(aws secretsmanager get-secret-value --secret-id ${RDSSECRETARN} | jq -r .SecretString | jq -r .password)
   inst1=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `DemoInstance1`].OutputValue' --output text)
   inst2=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `DemoInstance2`].OutputValue' --output text)
   dbname=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `RDSDBName`].OutputValue' --output text)

   cat ${SS_TEMPLATE} | sed "s/%DBNAME%/${dbname}/g" |  sed "s/%DB1EP%/${inst1}/g" | sed "s/%DB2EP%/${inst2}/g" | sed "s/%USERNAME%/${username}/g" | sed "s/%PASSWORD%/${password}/g" > ${SS_SQL}
   
}

function set_env()
{
    export INSTANCE_ROLE="C9Role"
    export EKS_STACK_NAME="eks-rds-ss-workshop"
    export EKS_CFN_FILE="${HOME}/environment/eks-rds-ss-workshop/eks-rds-ss-main.yaml"
    export EKS_NAMESPACE="kube-system"
    export SS_TEMPLATE="ss-distsql.tmpl"
    export SS_SQL="ss-distsql.sql"
    export AWS_REGION=`curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq .region -r`
    export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text) 
    export VPCID=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `VPC`].OutputValue' --output text)
    export SUBNETA=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `SubnetAPrivate`].OutputValue' --output text)
    export SUBNETB=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `SubnetBPrivate`].OutputValue' --output text)
    export SUBNETC=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `SubnetCPrivate`].OutputValue' --output text)
    export RDSSECRETARN=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `RDSSecretsArn`].OutputValue' --output text)
    export RDSSECURITYGROUP=$(aws cloudformation describe-stacks --region $AWS_REGION --query 'Stacks[].Outputs[?OutputKey == `RDSSecurityGroup`].OutputValue' --output text)
}

function fix_loadbalancer()
{
    loadbalancer_name=$(kubectl get service | grep LoadBalancer | awk '{print $4}' | awk -F'.' '{print $1}' | awk -F'-' '{print $1'})
    azA=$(aws ec2 describe-subnets --subnet-id ${SUBNETA} | jq -r .Subnets[0].AvailabilityZone)
    azB=$(aws ec2 describe-subnets --subnet-id ${SUBNETB} | jq -r .Subnets[0].AvailabilityZone)
    azC=$(aws ec2 describe-subnets --subnet-id ${SUBNETC} | jq -r .Subnets[0].AvailabilityZone)
    az_subA="${azA}_${SUBNETA}"
    az_subB="${azB}_${SUBNETB}"
    az_subC="${azC}_${SUBNETC}"

    assigned_subnet=$(aws elb describe-load-balancers --load-balancer-name af8feca71edf24048bd70696c6ed87e1 | jq -r .LoadBalancerDescriptions[0].Subnets[])
    azAssigned=$(aws ec2 describe-subnets --subnet-id ${assigned_subnet} | jq -r .Subnets[0].AvailabilityZone)

    echo ${assigned_subnet}

    for az_subnets in ${az_subA} ${az_subB} ${az_subC}
    do
	echo ${az_subnets}
	echo ${az_subnets} | grep ${azAssigned} > /dev/null 2>&1
	if [ $? -ne 0 ] ; then
	   newsubnet=`echo ${az_subnets} | awk -F'_' '{print $2}'` 
           newsubnets="${newsubnets} ${newsubnet}"
        fi
	echo ${newsubnets}
    done
    echo "aws elb attach-load-balancer-to-subnets --load-balancer-name ${loadbalancer_name} --subnets ${newsubnets}"
    aws elb attach-load-balancer-to-subnets --load-balancer-name ${loadbalancer_name} --subnets ${newsubnets}
}


# Main program starts here
export TERM1="/dev/null"
export TERM=xterm

if [ ${1}X == "fix_loadbalancerX" ] ; then
    set_env
    fix_loadbalancer
    exit
fi

echo "Process started at `date`"

install_packages
set_env
install_k8s_utilities
install_postgresql
chk_cloud9_permission
create_eks_cluster
export EKS_CLUSTER_NAME=$(aws cloudformation describe-stacks --query "Stacks[].Outputs[?(OutputKey == 'EKSClusterName')][].{OutputValue:OutputValue}" --output text)
export vpcsg=$(aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=5432 Name=ip-permission.to-port,Values=5432 --query "SecurityGroups[0].GroupId" --output text)
print_environment
update_kubeconfig
update_eks
install_loadbalancer
chk_installation
run_kubectl
print_line
print_line
generate_sql
echo "Process completed at `date`"
