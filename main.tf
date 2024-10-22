provider "aws" {
  region                   = "us-east-1"
  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "cf_challenge"
}
################################################################################
# VPC Module
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.14.0"

  name = "cf-vpc"
  cidr = "10.1.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.1.2.0/24", "10.1.3.0/24"]
  public_subnets  = ["10.1.0.0/24", "10.1.1.0/24"]

  enable_nat_gateway = true

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

################################################################################
# Creating EBS Key
################################################################################

resource "aws_kms_key" "ebs_key" {
  description         = "ebs key for ec2-module"
  policy              = data.aws_iam_policy_document.ebs_key.json
  enable_key_rotation = true
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "ebs_key" {
  statement {
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
  }
}

################################################################################
# EC2 Module
################################################################################

module "ec2_test" {
  source = "github.com/Coalfire-CF/terraform-aws-ec2"

  name = "redhat_instance"

  ami               = "ami-0583d8c7a9c35822c"
  ec2_instance_type = "t2.micro"
  instance_count    = 1
  ebs_optimized     = false

  vpc_id        = module.vpc.vpc_id
  subnet_ids    = [module.vpc.public_subnets[1]]
  associate_eip = true

  ec2_key_pair    = "ec2-module-test"
  ebs_kms_key_arn = aws_kms_key.ebs_key.arn

  # Storage
  root_volume_size = 20

  # Security Group Rules allowing inbound SSH from my IP and outbound to anywhere
  ingress_rules = {
    "ssh" = {
      ip_protocol = "tcp"
      from_port   = "22"
      to_port     = "22"
      cidr_ipv4   = "73.153.233.241/32" # Got an error message when this was set to cidr_blocks as opposed to cidr_ipv4
      description = "SSH"
    }
  }

  egress_rules = {
    "allow_all_egress" = {
      ip_protocol = "-1"
      from_port   = "0"
      to_port     = "0"
      cidr_ipv4   = "0.0.0.0/0"
      description = "Allow all egress"
    }
  }

  # Tagging
  global_tags = {}
}

################################################################################
# S3 Images Bucket
################################################################################
resource "aws_s3_bucket" "images" {
  bucket = "cf-tech-challenge-images-bucket"
}

resource "aws_s3_object" "archive_folder" {
  bucket = aws_s3_bucket.images.bucket
  key    = "Archive/"
}

resource "aws_s3_object" "memes_folder" {
  bucket = aws_s3_bucket.images.bucket
  key    = "Memes/"
}

resource "aws_s3_bucket_lifecycle_configuration" "memes_lifecycle" {
  bucket = aws_s3_bucket.images.bucket

  rule {
    id     = "move_old_memes_to_glacier"
    status = "Enabled"

    filter {
      prefix = "Memes/"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

################################################################################
# S3 Logs Bucket
################################################################################
resource "aws_s3_bucket" "logs" {
  bucket = "cf-tech-challenge-logs-bucket"
}

resource "aws_s3_object" "active_folder" {
  bucket = aws_s3_bucket.logs.bucket
  key    = "Active/"
}

resource "aws_s3_object" "inactive_folder" {
  bucket = aws_s3_bucket.logs.bucket
  key    = "Inactive/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs_lifecycle" {
  bucket = aws_s3_bucket.logs.bucket

  rule {
    id     = "move_old_active_items_to_glacier"
    status = "Enabled"

    filter {
      prefix = "Active/"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
  rule {
    id     = "delete_old_inactive_items"
    status = "Enabled"

    filter {
      prefix = "Inactive/"
    }

    expiration {
      days = 90
    }
  }
}

################################################################################
# Auto Scaling Group
################################################################################

# Launch Template for the Redhat Instances

resource "aws_launch_template" "rh_launch_template" {
  name          = "redhat_launch_template"
  instance_type = "t2.micro"

  image_id = "ami-0866a3c8686eaeeba"


  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 20
    }
  }

  #  user_data = 
}

data "aws_ami" "redhat" {
  most_recent = true
  owners      = ["099720109477"]
}

# Creating the Autoscaling Group

resource "aws_autoscaling_group" "cf_asg" {
  desired_capacity    = 2
  max_size            = 6
  min_size            = 2
  vpc_zone_identifier = module.vpc.private_subnets[*]

  launch_template {
    id      = aws_launch_template.rh_launch_template.id
    version = "$Latest"
  }

}

# Defining the IAM role to allow access to the Images bucket

resource "aws_iam_role" "asg_role" {
  name = "asg-s3-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "images_read_policy" {
  name        = "s3-read-policy"
  description = "Allow read access to images bucket"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = "s3:GetObject",
        Effect   = "Allow",
        Resource = "arn:aws:s3:::cf-tech-challenge-images-bucket/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_s3_read_policy" {
  role       = aws_iam_role.asg_role.name
  policy_arn = aws_iam_policy.images_read_policy.arn
}


# Security groups for the instances / load balancer

resource "aws_security_group" "instance_sg" {
  name        = "instance-sg"
  description = "Allow traffic for instances"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "lb_sg" {
  name        = "lb-sg"
  description = "Allow HTTP traffic for ALB"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["73.153.233.241/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


# Creating the Application Load Balancer

resource "aws_lb" "app_lb" {
  name               = "app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = [module.vpc.private_subnets[0], module.vpc.private_subnets[1]]

}

resource "aws_lb_listener" "app_lb_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

resource "aws_lb_target_group" "tg" {
  name     = "app-target-group"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = module.vpc.vpc_id

}

