
resource "aws_security_group" "postgresql" {
  name        = "askcto-postgresql-sg-${var.env}"
  description = "Security group for PostgreSQL database"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from eks security group"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "askcto-postgresql-sg-${var.env}"
  }
}
resource "aws_db_subnet_group" "postgresql" {
    name       = "askcto-postgresql-subnet-group"
    subnet_ids = var.private_worker_subnet_ids

    tags = {
        Name = "PostgreSQL subnet group for askcto"
        Environment = var.env
    }
}

resource "aws_db_instance" "postgresql" {
    identifier          = "askcto-db"
    engine              = "postgres"
    engine_version      = "16.3"
    instance_class      = "db.t3.small"
    allocated_storage   = 20
    storage_type        = "gp3"
    
    username            = "dbadmin"
    manage_master_user_password = true
    multi_az            = false
    
    vpc_security_group_ids = [aws_security_group.postgresql.id]  # Replace with your security group
    db_subnet_group_name   = aws_db_subnet_group.postgresql.name       
    
    skip_final_snapshot    = true
    
    backup_retention_period = 7

    tags = {
        Name = "PostgreSQL Database"
        Environment = "test"
    }
}
