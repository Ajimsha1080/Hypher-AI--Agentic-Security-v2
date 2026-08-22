# MCP Security Gateway — Enterprise VPC Deployment Guide

> For Fortune 500 and regulated industry customers who cannot route AI agent traffic through shared infrastructure.

---

## Architecture: Private VPC Deployment

```
Your VPC
├── ALB / NLB (with your SSL cert)
├── ECS/EKS cluster
│   └── mcp-security-gateway (your own container image)
├── RDS PostgreSQL (Multi-AZ, encrypted at rest)
├── ElastiCache Redis (encrypted in transit)
└── VPC Endpoints (no internet egress for DB/Redis)
```

No traffic ever leaves your VPC. The gateway container pulls from your private ECR registry. Database credentials never leave your AWS account.

---

## Terraform Module

```hcl
module "mcp_security_gateway" {
  source  = "github.com/antigravity/mcp-security-gateway//terraform/aws"
  version = "~> 3.0"

  # VPC settings
  vpc_id             = var.vpc_id
  private_subnet_ids = var.private_subnet_ids
  public_subnet_ids  = var.public_subnet_ids

  # Container image (build from source + push to your ECR)
  container_image = "${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/mcp-security-gateway:3.0.0"

  # Database (creates RDS PostgreSQL Multi-AZ)
  db_instance_class      = "db.t3.medium"    # or db.r6g.large for production
  db_multi_az            = true
  db_deletion_protection = true
  db_storage_encrypted   = true

  # Redis (creates ElastiCache Redis cluster)
  redis_node_type         = "cache.t3.micro"  # or cache.r6g.large
  redis_at_rest_encrypted = true
  redis_in_transit_encrypted = true

  # Application settings
  environment = {
    NODE_ENV         = "production"
    FAIL_MODE        = "fail_closed"
    ENABLE_DASHBOARD = "true"
    CLOUD_DOMAIN     = var.custom_domain   # e.g. ai-security.yourcompany.com
    LOG_LEVEL        = "info"
  }

  # Secrets (stored in AWS Secrets Manager — never in plaintext)
  secrets_manager_prefix = "/mcp-security/${var.environment}"
  # Secrets Manager should contain:
  #   JWT_SECRET, ADMIN_SECRET, STRIPE_SECRET_KEY,
  #   GOOGLE_CLIENT_SECRET, OKTA_CLIENT_SECRET, etc.

  # ALB settings
  certificate_arn    = var.acm_certificate_arn
  allowed_cidr_blocks = var.allowed_cidr_blocks   # restrict ALB access to your offices/VPN

  # Auto-scaling
  min_capacity = 2    # always run 2 for HA
  max_capacity = 10
  cpu_target   = 60

  tags = var.tags
}

output "gateway_url" {
  value = module.mcp_security_gateway.alb_dns_name
}

output "dashboard_url" {
  value = "https://${module.mcp_security_gateway.alb_dns_name}/dashboard"
}
```

---

## Quick Deploy (ECS Fargate)

### 1. Build and push your container image

```bash
# Clone the repo
git clone https://github.com/antigravity/mcp-security-gateway
cd mcp-security-gateway

# Build
docker build -t mcp-security-gateway:3.0.0 .

# Push to your ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com

docker tag mcp-security-gateway:3.0.0 \
  123456789.dkr.ecr.us-east-1.amazonaws.com/mcp-security-gateway:3.0.0

docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/mcp-security-gateway:3.0.0
```

### 2. Store secrets in AWS Secrets Manager

```bash
aws secretsmanager create-secret \
  --name /mcp-security/production/JWT_SECRET \
  --secret-string "$(openssl rand -hex 32)"

aws secretsmanager create-secret \
  --name /mcp-security/production/ADMIN_SECRET \
  --secret-string "$(openssl rand -hex 32)"

# Add Stripe, OAuth credentials similarly
```

### 3. Run migrations against your RDS instance

```bash
DATABASE_URL="postgresql://mcp_admin:password@your-rds.cluster.us-east-1.rds.amazonaws.com/mcp_security" \
  npm run db:migrate
```

### 4. Apply Terraform

```bash
cd terraform/aws
terraform init
terraform plan -var-file=production.tfvars
terraform apply
```

---

## Kubernetes Helm Chart

```bash
helm repo add mcp-security https://charts.mcpsecurity.dev
helm repo update

helm install mcp-security mcp-security/gateway \
  --namespace mcp-security \
  --create-namespace \
  --set image.repository=your-registry/mcp-security-gateway \
  --set image.tag=3.0.0 \
  --set database.host=your-postgres.internal \
  --set redis.host=your-redis.internal \
  --set ingress.enabled=true \
  --set ingress.host=ai-security.yourcompany.com \
  --set ingress.tls.secretName=your-tls-secret \
  -f values-production.yaml
```

---

## Security Checklist for Enterprise VPC Deployment

| Requirement | How to achieve |
|---|---|
| No internet egress for DB | Use VPC endpoints for RDS + ElastiCache |
| Secrets never in plaintext | AWS Secrets Manager + IAM role for ECS task |
| Encryption at rest | RDS storage_encrypted=true, ElastiCache at_rest_encrypted=true |
| Encryption in transit | ALB → TLS 1.2+, Redis in_transit_encrypted=true |
| Audit log immutability | hash-chained audit log (built-in), optionally ship to CloudWatch Logs |
| Network isolation | security groups restrict: DB accessible only from ECS, Redis accessible only from ECS |
| High availability | Multi-AZ RDS, 2+ ECS tasks across AZs |
| Container scanning | Scan ECR image with Amazon Inspector before deploy |
| Key rotation | AWS KMS for DB encryption key, Secrets Manager auto-rotation for DB password |

---

## GCP / Azure Equivalents

**GCP:** Use Cloud Run + Cloud SQL (PostgreSQL) + Memorystore (Redis). Cloud Run handles auto-scaling and HTTPS termination. IAM service accounts replace AWS IAM roles.

**Azure:** Use Azure Container Apps + Azure Database for PostgreSQL + Azure Cache for Redis. Managed Identity replaces service accounts. Azure Key Vault replaces AWS Secrets Manager.

---

## Support

Enterprise VPC deployments include dedicated onboarding support. Contact `enterprise@mcpsecurity.dev` with subject "VPC Deployment" to schedule a 2-hour deployment session with the engineering team.
