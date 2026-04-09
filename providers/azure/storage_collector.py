"""
Azure Storage Posture Collector
================================
Collects Azure Storage Account configurations to assess security posture:
  - HTTPS-only enforcement
  - Public blob access settings
  - Encryption at rest (default: enabled, but check key source)
  - Minimum TLS version
  - Shared key access (can be disabled in favour of AAD-only)

Permissions required (read-only):
  - Reader role on the target subscription, or at minimum
    Microsoft.Storage/storageAccounts/read on all storage accounts.

Use only on subscriptions you are authorised to assess.
"""
from dataclasses import dataclass, field
from typing import Optional

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient


@dataclass
class StorageAccountPosture:
    """Posture data for a single Azure Storage Account."""
    name: str
    resource_group: str
    location: str
    https_only: bool                    # Secure transfer required
    public_blob_access_allowed: bool    # True if any container can be public
    min_tls_version: str                # e.g. "TLS1_2"
    allow_shared_key_access: bool       # If False, only AAD auth is permitted
    encryption_key_source: str          # "Microsoft.Storage" or "Microsoft.Keyvault"
    risk_flags: list[str] = field(default_factory=list)


def _build_credential(
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
):
    """
    Build an Azure credential object.

    If service principal credentials are provided, uses ClientSecretCredential.
    Otherwise falls back to DefaultAzureCredential (env vars, managed identity, etc.).
    """
    if tenant_id and client_id and client_secret:
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    # DefaultAzureCredential supports env vars, workload identity, managed identity, CLI, etc.
    return DefaultAzureCredential()


def assess_storage_account_posture(
    subscription_id: str,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> list[StorageAccountPosture]:
    """
    Assess posture of all Storage Accounts in the given Azure subscription.

    Args:
        subscription_id: Azure subscription UUID.
        tenant_id: Service principal tenant (optional, falls back to DefaultAzureCredential).
        client_id: Service principal app ID (optional).
        client_secret: Service principal secret (optional).

    Returns:
        List of StorageAccountPosture objects with risk flags populated.
    """
    credential = _build_credential(tenant_id, client_id, client_secret)
    client = StorageManagementClient(credential, subscription_id)

    results = []

    for account in client.storage_accounts.list():
        flags: list[str] = []

        # HTTPS-only (secure transfer required)
        https_only = account.enable_https_traffic_only or False
        if not https_only:
            flags.append("https_not_enforced")

        # Public blob access — if True, individual containers may be made public
        public_blob_access_allowed = account.allow_blob_public_access or False
        if public_blob_access_allowed:
            flags.append("public_blob_access_allowed")

        # Minimum TLS version
        min_tls = (account.minimum_tls_version or "TLS1_0").value if hasattr(
            account.minimum_tls_version, "value"
        ) else str(account.minimum_tls_version or "TLS1_0")
        if min_tls not in ("TLS1_2", "TLS1_3"):
            flags.append(f"weak_tls_version:{min_tls}")

        # Shared key access — disabling it forces AAD-only authentication
        allow_shared_key = account.allow_shared_key_access
        if allow_shared_key is None:
            allow_shared_key = True  # Default is enabled when not explicitly set
        if allow_shared_key:
            flags.append("shared_key_access_enabled")

        # Encryption key source
        encryption_key_source = "unknown"
        if account.encryption and account.encryption.key_source:
            ks = account.encryption.key_source
            encryption_key_source = ks.value if hasattr(ks, "value") else str(ks)
        # Microsoft-managed keys are acceptable; customer-managed keys are preferred for strict profile
        if encryption_key_source == "Microsoft.Storage":
            flags.append("customer_managed_key_not_used")

        # Parse resource group from the account's ID string
        resource_group = "unknown"
        if account.id:
            parts = account.id.split("/")
            try:
                rg_idx = parts.index("resourceGroups")
                resource_group = parts[rg_idx + 1]
            except (ValueError, IndexError):
                pass

        results.append(StorageAccountPosture(
            name=account.name or "unnamed",
            resource_group=resource_group,
            location=account.location or "unknown",
            https_only=https_only,
            public_blob_access_allowed=public_blob_access_allowed,
            min_tls_version=min_tls,
            allow_shared_key_access=allow_shared_key,
            encryption_key_source=encryption_key_source,
            risk_flags=flags,
        ))

    return results
