"""
Clouds8 - Seed Data Script
Generates and loads comprehensive dummy data into the database for demonstration purposes.
"""

import sys
import os
import random
from datetime import datetime
import json

from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Must run before the db.database import below, which reads
# INTERNAL_SERVICE_TOKEN at module-import time (see
# docs/superpowers/specs/2026-10-04-admin-auth-design.md).
load_dotenv()

from db.database import init_database, import_assets, clear_database

def generate_dummy_data():
    """Generate a rich set of dummy OCI assets."""
    assets = []
    
    # Define environment structures
    regions = ["us-phoenix-1", "us-ashburn-1", "eu-frankfurt-1"]
    compartments = [
        "root", 
        "Network-Prod", "App-Prod", "DB-Prod",
        "Network-Dev", "App-Dev", "DB-Dev",
        "Security-Zone", "Sandbox"
    ]
    lifecycle_states = ["RUNNING", "STOPPED", "TERMINATED", "PROVISIONING"]
    
    print("generating dummy data...")

    # 1. IAM Resources (Global)
    groups = ["Administrators", "Developers", "Auditors", "NetworkAdmins"]
    for group in groups:
        assets.append({
            "asset_id": f"ocid1.group.oc1..{group.lower()}",
            "asset_type": "group",
            "name": group,
            "compartment": "root",
            "region": "global",
            "metadata": {
                "description": f"{group} Group",
                "time_created": "2023-01-15T10:00:00Z"
            }
        })

    users = ["alice.admin", "bob.dev", "charlie.auditor", "dave.net"]
    for i, user in enumerate(users):
        assets.append({
            "asset_id": f"ocid1.user.oc1..{user}",
            "asset_type": "user",
            "name": user,
            "compartment": "root",
            "region": "global",
            "metadata": {
                "email": f"{user}@company.com",
                "is_mfa_activated": random.choice([True, False]),
                "time_created": "2023-02-01T14:30:00Z"
            }
        })

    policies = [
        ("Manage-All", "Allow group Administrators to manage all-resources in tenancy"),
        ("View-Audit", "Allow group Auditors to read all-resources in tenancy"),
        ("Manage-Net", "Allow group NetworkAdmins to manage virtual-network-family in tenancy"),
    ]
    for name, stmt in policies:
        assets.append({
            "asset_id": f"ocid1.policy.oc1..{name.lower()}",
            "asset_type": "policy",
            "name": name,
            "compartment": "root",
            "region": "global",
            "scan_status": "scanned",
            "risk_score": random.randint(0, 20),
            "metadata": {
                "statements": [stmt],
                "description": f"Policy for {name}"
            }
        })

    # 2. Regional Resources
    for comp in compartments:
        if comp == "root": continue
        
        # Pick a primary region for this compartment
        region = random.choice(regions)
        
        # VCN (1 per compartment usually)
        vcn_name = f"{comp}-VCN"
        assets.append({
            "asset_id": f"ocid1.vcn.oc1.{region}.{comp.lower()}",
            "asset_type": "vcn",
            "name": vcn_name,
            "compartment": comp,
            "region": region,
            "metadata": {
                "cidr_block": "10.0.0.0/16",
                "dns_label": comp.lower().replace("-", ""),
                "lifecycle_state": "AVAILABLE"
            }
        })

        # Subnets (Public/Private)
        for sub_type in ["Public", "Private"]:
            sub_name = f"{comp}-{sub_type}-Subnet"
            assets.append({
                "asset_id": f"ocid1.subnet.oc1.{region}.{comp.lower()}-{sub_type.lower()}",
                "asset_type": "subnet",
                "name": sub_name,
                "compartment": comp,
                "region": region,
                "risk_score": 50 if sub_type == "Public" else 10,
                "metadata": {
                    "cidr_block": "10.0.1.0/24" if sub_type == "Public" else "10.0.2.0/24",
                    "prohibit_public_ip_on_vnic": sub_type == "Private",
                    "lifecycle_state": "AVAILABLE"
                }
            })

        # Compute Instances
        count = random.randint(2, 8)
        for i in range(count):
            inst_name = f"{comp}-server-{i+1:02d}"
            is_public = "Public" if i < 2 else "Private" # First few might be public
            shape = random.choice(["VM.Standard2.1", "VM.Standard.E4.Flex", "BM.Standard2.52"])
            assets.append({
                "asset_id": f"ocid1.instance.oc1.{region}.{inst_name}",
                "asset_type": "vm",
                "name": inst_name,
                "compartment": comp,
                "region": region,
                "risk_score": random.randint(0, 90),
                "metadata": {
                    "shape": shape,
                    "lifecycle_state": random.choice(lifecycle_states),
                    "availability_domain": f"{region.upper()}-AD-{random.randint(1,3)}",
                    "time_created": datetime.now().isoformat()
                }
            })
            
            # Associated VNIC
            assets.append({
                "asset_id": f"ocid1.vnic.oc1.{region}.{inst_name}-vnic",
                "asset_type": "vnic",
                "name": f"{inst_name}-primary-vnic",
                "compartment": comp,
                "region": region,
                "metadata": {
                    "public_ip": f"129.156.{random.randint(0,255)}.{random.randint(0,255)}" if is_public == "Public" else None,
                    "private_ip": f"10.0.{random.randint(1,2)}.{random.randint(2,254)}",
                    "is_primary": True
                }
            })

        # Buckets
        if "App" in comp or "Backup" in comp:
            bucket_name = f"{comp.lower()}-assets-{random.randint(1000,9999)}"
            is_public = "Public" in bucket_name or random.random() < 0.2
            assets.append({
                "asset_id": bucket_name,
                "asset_type": "bucket",
                "name": bucket_name,
                "compartment": comp,
                "region": region,
                "risk_score": 80 if is_public else 10,
                "metadata": {
                    "namespace": "clouds8-demo",
                    "public_access_type": "ObjectRead" if is_public else "NoPublicAccess",
                    "storage_tier": "Standard"
                }
            })

        # Load Balancers
        if "Prod" in comp:
             lb_name = f"{comp}-LB-01"
             assets.append({
                "asset_id": f"ocid1.loadbalancer.oc1.{region}.{lb_name}",
                "asset_type": "lb",
                "name": lb_name,
                "compartment": comp,
                "region": region,
                "metadata": {
                    "shape_name": "100Mbps",
                    "is_private": False,
                    "lifecycle_state": "ACTIVE",
                    "ip_addresses": ["130.1.2.3"]
                }
            })

    return assets

def run_seed():
    """Clear DB and load dummy data."""
    print("🧹 Clearing existing database...")
    clear_database()
    
    # Re-init to ensure tables exist
    init_database()
    
    data = generate_dummy_data()
    print(f"📦 Generated {len(data)} dummy assets.")
    
    stats = import_assets(data, source_description="Dummy Data Seed Script")
    print("\n✅ Data Load Complete!")
    print(f"  Total Imported: {stats['imported']}")
    print(f"  Errors: {stats['errors']}")
    print("\nSummary by Type:")
    for atype, count in stats['by_type'].items():
        print(f"  - {atype}: {count}")

if __name__ == "__main__":
    run_seed()
