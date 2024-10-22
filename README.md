This Terraform code is written for the Coalfire AWS Technical Challenge.

This code creates a VPC with CIDR 10.1.0.0/16 and 4 subnets (2 public, 2 private), spread out across two availability zones. 

A standalone t2.micro EC2 instance running RHEL is created, running in one of the public subnets.

Two S3 buckets are created, both with their own Lifecycle rules for object management.

An Auto Scaling group is created with a minimum of 2 instances, and a maximum of 6. Instances are spread out across the two private subnets, and are granted an IAM role to allow access to the Images S3 bucket. An Application Load Balancer is created to listen on TCP port 80 (HTTP) and forward traffic to the ASG in the private subnets
on port 443.
