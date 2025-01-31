module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "ascending-askcto-cluster"
  cluster_version = var.cluster_version

  cluster_endpoint_public_access = true

  cluster_addons = {
    coredns                = { resolve_conflicts_on_update  = "OVERWRITE" , addon_version = "v1.11.4-eksbuild.2" }
    # eks-pod-identity-agent = { resolve_conflicts = "OVERWRITE" }
    kube-proxy             = { resolve_conflicts = "OVERWRITE" }
    vpc-cni                = { resolve_conflicts = "OVERWRITE" }
    amazon-cloudwatch-observability = { resolve_conflicts = "OVERWRITE" }
    # aws-ebs-csi-driver     = { resolve_conflicts = "OVERWRITE" }
  }

  vpc_id                   = var.vpc_id
  subnet_ids               = var.private_worker_subnet_ids
  control_plane_subnet_ids = var.private_cluster_subnet_ids

  kms_key_owners = ["arn:aws:iam::595312265488:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AWSAdministratorAccess_2d343f337de98862"]

  # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    capacity_type = var.capacity_type
  }

  eks_managed_node_groups = {
    system_node = {
      # Starting on 1.30, AL2023 is the default AMI type for EKS managed node groups
      instance_types = ["t3a.medium","t3.medium"]
      ami_type       = "AL2023_x86_64_STANDARD"
      min_size       = 1
      max_size       = 2
      desired_size   = 1
    }
  }

  # # Cluster access entry
  # # To add the current caller identity as an administrator
  # enable_cluster_creator_admin_permissions = true

  access_entries = {
    # One access entry with a policy associated
    # github = {
    #   principal_arn = "arn:aws:iam::595312265488:role/GithubActionAssumeRole"

    #   policy_associations = {
    #     admin = {
    #       policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    #       access_scope = {
    #         type = "cluster"
    #       }
    #     }
    #   }
    # },
    admin_user = {
      principal_arn = "arn:aws:iam::595312265488:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AWSAdministratorAccess_2d343f337de98862"

      policy_associations = {
        admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }

  tags = {
    Environment = "dev"
    Terraform   = "true"
  }
}

resource "aws_eks_addon" "aws-ebs-csi-driver" {
  cluster_name             = module.eks.cluster_name
  addon_name               = "aws-ebs-csi-driver"
  addon_version            = "v1.38.1-eksbuild.2"
  resolve_conflicts_on_update        = "OVERWRITE"
  service_account_role_arn = "arn:aws:iam::595312265488:role/AmazonEKS_EBS_CSI_DriverRole"

  configuration_values = jsonencode({
    sidecars: {
      snapshotter: {
        forceEnable: false
      }
    }
  })

}