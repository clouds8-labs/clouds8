"""
Proof-of-Concept command templates for findings.

Findings carry only asset_id (OCID), asset_name, and account (compartment)
by the time they reach the DB (see store._finding_row_to_v1) - these
templates are written against exactly those fields, nothing more. Keyed by
check_id, with a small prefix table for the dynamically-suffixed ids
(vm-meta-{source}, bucket-secret-{source}) and one generic fallback for
anything unmapped.
"""
from typing import Dict, Optional

TEMPLATES: Dict[str, str] = {
    # VM
    "vm-public-ip": "oci compute instance list-vnics --instance-id {asset_id}",
    "vm-imds-v1": "oci compute instance get --instance-id {asset_id} --query 'data.\"instance-options\"'",
    "vm-cloud-init": "oci compute instance get --instance-id {asset_id} --query 'data.metadata.\"user_data\"'",
    # Bucket
    "bucket-public": "oci os bucket get --bucket-name {asset_name} --query 'data.\"public-access-type\"'",
    # Vault
    "vault-key-rotation": "oci kms management key get --key-id {asset_id} --endpoint <management-endpoint>",
    # Autonomous DB
    "adb-mtls-disabled": "oci db autonomous-database get --autonomous-database-id {asset_id} --query 'data.\"is-mtls-connection-required\"'",
    "adb-public-unrestricted": "oci db autonomous-database get --autonomous-database-id {asset_id} --query 'data.\"whitelisted-ips\"'",
    "adb-public-access": "oci db autonomous-database get --autonomous-database-id {asset_id} --query 'data.\"subnet-id\",data.\"nsg-ids\"'",
    "adb-no-network-restriction": "oci db autonomous-database get --autonomous-database-id {asset_id} --query 'data.\"whitelisted-ips\"'",
    "adb-no-nsg": "oci db autonomous-database get --autonomous-database-id {asset_id} --query 'data.\"nsg-ids\"'",
    "adb-unhealthy-state": "oci db autonomous-database get --autonomous-database-id {asset_id} --query 'data.\"lifecycle-state\"'",
    "adb-free-tier": "oci db autonomous-database get --autonomous-database-id {asset_id} --query 'data.\"is-free-tier\"'",
    "adb-check": "oci db autonomous-database get --autonomous-database-id {asset_id}",
    # Block volumes
    "volume-faulty": "oci bv volume get --volume-id {asset_id} --query 'data.\"lifecycle-state\"'",
    "volume-no-backup-policy": "oci bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment --asset-id {asset_id}",
    "volume-no-kms": "oci bv volume get --volume-id {asset_id} --query 'data.\"kms-key-id\"'",
    "volume-unattached": "oci compute volume-attachment list --compartment-id <compartment-ocid> --volume-id {asset_id}",
    "volume-check": "oci bv volume get --volume-id {asset_id}",
    # Images
    "image-legacy-firmware": "oci compute image get --image-id {asset_id} --query 'data.\"launch-options\".firmware'",
    "image-management-disabled": "oci compute image get --image-id {asset_id} --query 'data.\"agent-features\"'",
    "image-monitoring-disabled": "oci compute image get --image-id {asset_id} --query 'data.\"agent-features\".\"is-monitoring-supported\"'",
    "image-pv-encryption-disabled": "oci compute image get --image-id {asset_id} --query 'data.\"launch-options\".\"is-pv-encryption-in-transit-enabled\"'",
    "image-stale": "oci compute image get --image-id {asset_id} --query 'data.\"time-created\"'",
    "image-check": "oci compute image get --image-id {asset_id}",
    # IAM users/groups/dynamic groups
    "user-mfa-disabled": "oci iam user list-api-keys --user-id {asset_id}",
    "user-api-key-stale": "oci iam user list-api-keys --user-id {asset_id} --query 'data[*].\"time-created\"'",
    "user-api-key-sprawl": "oci iam user list-api-keys --user-id {asset_id}",
    "iam-user-check": "oci iam user get --user-id {asset_id}",
    "group-empty": "oci iam group list-users --group-id {asset_id}",
    "iam-group-check": "oci iam group get --group-id {asset_id}",
    "dynamicgroup-no-matching-rule": "oci iam dynamic-group get --dynamic-group-id {asset_id} --query 'data.\"matching-rule\"'",
    "dynamicgroup-broad-compartment-match": "oci iam dynamic-group get --dynamic-group-id {asset_id} --query 'data.\"matching-rule\"'",
    "iam-dynamicgroup-check": "oci iam dynamic-group get --dynamic-group-id {asset_id}",
    "iam-policy-check": "oci iam policy get --policy-id {asset_id}",
    # OKE
    "oke-dashboard-enabled": "oci ce cluster get --cluster-id {asset_id} --query 'data.\"addons\"'",
    "oke-deprecated-k8s-version": "oci ce cluster get --cluster-id {asset_id} --query 'data.\"kubernetes-version\"'",
    "oke-image-policy-disabled": "oci ce cluster get --cluster-id {asset_id} --query 'data.\"image-policy-config\"'",
    "oke-nodepool-version-skew": "oci ce node-pool list --cluster-id {asset_id} --compartment-id <compartment-ocid> --query 'data[*].\"kubernetes-version\"'",
    "oke-public-api-endpoint": "oci ce cluster get --cluster-id {asset_id} --query 'data.\"endpoint-config\".\"is-public-ip-enabled\"'",
    "oke-tiller-enabled": "oci ce cluster get --cluster-id {asset_id} --query 'data.\"addons\"'",
    "oke-check": "oci ce cluster get --cluster-id {asset_id}",
    # Functions
    "functions-image-policy-disabled": "oci fn application get --application-id {asset_id} --query 'data.\"image-policy-config\"'",
    "functions-no-subnets": "oci fn application get --application-id {asset_id} --query 'data.\"subnet-ids\"'",
    "functions-secret-in-env": "oci fn application get --application-id {asset_id} --query 'data.\"config\"'",
    "functions-trace-disabled": "oci fn application get --application-id {asset_id} --query 'data.\"trace-config\"'",
    "functions-check": "oci fn application get --application-id {asset_id}",
    # CIS benchmark - same generic "inspect the flagged resource" shape across checks
    "CIS-1.1": "oci iam user list-api-keys --user-id {asset_id}",
    "CIS-1.2": "oci iam user list-api-keys --user-id {asset_id} --query 'data[*].\"time-created\"'",
    "CIS-1.3": "oci iam user get --user-id {asset_id} --query 'data.\"is-mfa-activated\"'",
    "CIS-1.4": "oci iam user get --user-id {asset_id}",
    "CIS-1.5": "oci iam group list-users --group-id {asset_id}",
    "CIS-1.6": "oci iam dynamic-group get --dynamic-group-id {asset_id} --query 'data.\"matching-rule\"'",
    "CIS-1.7": "oci iam policy get --policy-id {asset_id}",
    "CIS-2.1": "oci network security-list get --security-list-id {asset_id}",
    "CIS-2.2": "oci network security-list get --security-list-id {asset_id} --query 'data.\"ingress-security-rules\"'",
    "CIS-2.3": "oci network nsg list-rules --nsg-id {asset_id}",
    "CIS-2.4": "oci network security-list get --security-list-id {asset_id}",
    "CIS-3.1": "oci logging log-group list --compartment-id <compartment-ocid>",
    "CIS-3.2": "oci audit configuration get --compartment-id <compartment-ocid>",
    "CIS-3.3": "oci events rule list --compartment-id <compartment-ocid>",
    "CIS-4.1": "oci os bucket get --bucket-name {asset_name} --query 'data.\"public-access-type\"'",
    "CIS-4.2": "oci os bucket get --bucket-name {asset_name} --query 'data.\"kms-key-id\"'",
    "CIS-4.3": "oci bv volume get --volume-id {asset_id} --query 'data.\"kms-key-id\"'",
    "CIS-4.4": "oci db autonomous-database get --autonomous-database-id {asset_id} --query 'data.\"kms-key-id\"'",
    "CIS-5.1": "oci network vcn get --vcn-id {asset_id}",
    "CIS-5.2": "oci network subnet get --subnet-id {asset_id} --query 'data.\"prohibit-public-ip-on-vnic\"'",
    "CIS-6.1": "oci compute instance get --instance-id {asset_id} --query 'data.\"instance-options\"'",
    "cis-check": "oci search resource structured-search --query-text \"query all resources where identifier = '{asset_id}'\"",

    # GCP VM
    "gcp-vm-public-ip": "gcloud compute instances describe {asset_name} --project={account} --format='value(networkInterfaces[].accessConfigs[].natIP)'",
    "gcp-vm-default-sa-full-access": "gcloud compute instances describe {asset_name} --project={account} --format='value(serviceAccounts)'",
    "gcp-vm-serial-port-enabled": "gcloud compute instances get-serial-port-output {asset_name} --project={account}",
    "gcp-vm-shielded-incomplete": "gcloud compute instances describe {asset_name} --project={account} --format='value(shieldedInstanceConfig)'",
    "gcp-vm-check": "gcloud compute instances describe {asset_name} --project={account}",

    # GCP GCS buckets
    "gcp-bucket-public": "gsutil iam get gs://{asset_name}",
    "gcp-bucket-no-uniform-access": "gcloud storage buckets describe gs://{asset_name} --format='value(uniformBucketLevelAccess)'",
    "gcp-bucket-no-versioning": "gsutil versioning get gs://{asset_name}",
    "gcp-bucket-no-pap": "gcloud storage buckets describe gs://{asset_name} --format='value(publicAccessPrevention)'",
    "gcp-bucket-no-cmek": "gsutil kms encryption gs://{asset_name}",
    "gcp-bucket-check": "gsutil ls -L -b gs://{asset_name}",

    # GCP IAM / service accounts
    "gcp-iam-sa-user-keys": "gcloud iam service-accounts keys list --iam-account={asset_name} --project={account}",
    "gcp-iam-sa-public-binding": "gcloud iam service-accounts get-iam-policy {asset_name} --project={account}",
    "gcp-iam-sa-token-creator": "gcloud iam service-accounts get-iam-policy {asset_name} --project={account}",
    "gcp-iam-check": "gcloud iam service-accounts describe {asset_name} --project={account}",

    # GCP privilege-escalation detections (project-scoped, not per-asset)
    "gcp-privesc-iam_serviceaccounts_getaccesstoken": (
        "curl -s -X POST -H \"Authorization: Bearer $(gcloud auth print-access-token)\" "
        "\"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:generateAccessToken\" "
        "-d '{{\"scope\":[\"https://www.googleapis.com/auth/cloud-platform\"]}}'"
    ),
    "gcp-privesc-iam_serviceaccountkeys_create": "gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA --project={account}",
    "gcp-privesc-resourcemanager_projects_setiampolicy": "gcloud projects add-iam-policy-binding {account} --member='user:attacker@example.com' --role='roles/owner'",
    "gcp-privesc-iam_roles_update": "gcloud iam roles describe TARGET_ROLE --project={account}",
    "gcp-privesc-cloudbuild_builds_create": "gcloud builds submit --project={account} --no-source --config=cloudbuild.yaml",

    # GCP Cloud SQL
    "gcp-db-public-ip": "gcloud sql instances describe {asset_name} --project={account} --format='value(ipAddresses)'",
    "gcp-db-open-authorized-network": "gcloud sql instances describe {asset_name} --project={account} --format='value(settings.ipConfiguration.authorizedNetworks)'",
    "gcp-db-ssl-not-required": "gcloud sql instances describe {asset_name} --project={account} --format='value(settings.ipConfiguration.requireSsl)'",
    "gcp-db-no-backups": "gcloud sql instances describe {asset_name} --project={account} --format='value(settings.backupConfiguration)'",
    "gcp-db-no-pitr": "gcloud sql instances describe {asset_name} --project={account} --format='value(settings.backupConfiguration.pointInTimeRecoveryEnabled)'",
    "gcp-db-check": "gcloud sql instances describe {asset_name} --project={account}",

    # GCP CIS benchmark
    "GCP-CIS-1.4": "gcloud projects get-iam-policy {account} --format=json",
    "GCP-CIS-3.2": "gcloud compute firewall-rules list --project={account} --filter='sourceRanges:0.0.0.0/0 AND allowed.ports:22'",
    "GCP-CIS-4.2": "gcloud compute instances list --project={account} --filter='EXTERNAL_IP:*'",
    "GCP-CIS-5.1": "gsutil iam get gs://{asset_id}",
    "GCP-CIS-6.1": "gcloud sql instances describe {asset_id} --project={account} --format='value(ipAddresses)'",
}

PREFIX_TEMPLATES: Dict[str, str] = {
    "vm-meta-": "oci compute instance get --instance-id {asset_id} --query 'data.metadata,data.\"extended-metadata\"'",
    "bucket-secret-": "oci os object list --bucket-name {asset_name} --all",
    "bucket-": "oci os bucket get --bucket-name {asset_name}",
    "gcp-privesc-": "gcloud projects get-iam-policy {account} --format=json",
    "gcp-vm-": "gcloud compute instances describe {asset_name} --project={account}",
    "gcp-bucket-": "gsutil ls -L -b gs://{asset_name}",
    "gcp-iam-": "gcloud iam service-accounts describe {asset_name} --project={account}",
    "gcp-db-": "gcloud sql instances describe {asset_name} --project={account}",
    "GCP-CIS-": "gcloud projects describe {account}",
}

GENERIC_TEMPLATE = "oci search resource structured-search --query-text \"query all resources where identifier = '{asset_id}'\""


def render(check_id: Optional[str], row: Dict) -> Optional[str]:
    """Render a PoC command for a finding row. Returns None if asset_id is
    unavailable (nothing to interpolate)."""
    asset_id = row.get("asset_id")
    if not check_id or not asset_id:
        return None

    template = TEMPLATES.get(check_id)
    if template is None:
        for prefix, prefix_template in PREFIX_TEMPLATES.items():
            if check_id.startswith(prefix):
                template = prefix_template
                break
    if template is None:
        template = GENERIC_TEMPLATE

    return template.format(
        asset_id=asset_id,
        asset_name=row.get("asset_name") or asset_id,
        account=row.get("account") or row.get("compartment") or "<compartment>",
    )


def _demo():
    row = {"asset_id": "ocid1.instance.oc1..abc", "asset_name": "web-01", "account": "prod"}
    assert render(None, row) is None
    assert render("vm-public-ip", {"asset_id": None}) is None
    assert "ocid1.instance.oc1..abc" in render("vm-public-ip", row)
    assert "ocid1.instance.oc1..abc" in render("vm-meta-secrets", row)  # prefix fallback
    assert render("totally-unknown-check", row) == GENERIC_TEMPLATE.format(asset_id=row["asset_id"])
    print("poc_templates: ok")


if __name__ == "__main__":
    _demo()
