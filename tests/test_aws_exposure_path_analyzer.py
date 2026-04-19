from analyzers.aws_exposure_path_analyzer import analyze_aws_exposure_paths


def test_detects_reachable_eni_via_igw_route_and_world_open_sg():
    evidence = {
        "security_groups": [
            {
                "GroupId": "sg-open",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ],
        "subnets": [{"SubnetId": "subnet-a", "VpcId": "vpc-1"}],
        "route_tables": [
            {
                "RouteTableId": "rtb-1",
                "VpcId": "vpc-1",
                "Associations": [{"SubnetId": "subnet-a"}],
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"}],
            }
        ],
        "network_interfaces": [
            {
                "NetworkInterfaceId": "eni-1",
                "SubnetId": "subnet-a",
                "Groups": [{"GroupId": "sg-open"}],
            }
        ],
    }

    result = analyze_aws_exposure_paths(evidence)
    assert result["summary"]["total_paths"] == 1
    finding = result["findings"][0]
    assert finding["target_id"] == "eni-1"
    assert "tcp:443" in finding["reachable_ports"]
    assert finding["internet_via"].startswith("igw-")


def test_does_not_flag_private_subnet_without_igw_default_route():
    evidence = {
        "security_groups": [
            {
                "GroupId": "sg-open",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ],
        "subnets": [{"SubnetId": "subnet-private", "VpcId": "vpc-1"}],
        "route_tables": [
            {
                "RouteTableId": "rtb-private",
                "VpcId": "vpc-1",
                "Associations": [{"SubnetId": "subnet-private"}],
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}],
            }
        ],
        "network_interfaces": [
            {
                "NetworkInterfaceId": "eni-private",
                "SubnetId": "subnet-private",
                "Groups": [{"GroupId": "sg-open"}],
            }
        ],
    }

    result = analyze_aws_exposure_paths(evidence)
    assert result["summary"]["total_paths"] == 0
    assert result["findings"] == []
