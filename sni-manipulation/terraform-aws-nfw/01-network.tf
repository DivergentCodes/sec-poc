
###########################################################
# VPC and Networking
###########################################################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

###########################################################
# Public subnet
###########################################################

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  availability_zone = "${var.region}${var.availability_zone}"
  cidr_block        = var.public_subnet_cidr

  # Automatic assignment of public IPs is part of what makes this a "public" subnet.
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-route-table"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

###########################################################
# Private subnet
###########################################################

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  availability_zone = "${var.region}${var.availability_zone}"
  cidr_block        = var.private_subnet_cidr

  tags = {
    Name = "${var.project_name}-private-subnet"
  }
}

# Create the route table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-private-route-table"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id

  depends_on = [
    aws_route_table.private,
  ]
}
