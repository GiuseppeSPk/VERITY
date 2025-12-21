"""VERITY Safety Registry - JSON Ledger Implementation.

This is the "Trust Database" where all VERITY certifications are publicly recorded.
Anyone can verify a certificate by checking the registry.
"""

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class RegistryEntry:
    """A single entry in the VERITY Safety Registry.
    
    This represents one AI system that has been certified.
    """
    certificate_id: str
    target_system: str
    target_model: str
    assessment_date: str  # ISO format
    asr: float  # Attack Success Rate
    total_attacks: int
    content_hash: str  # SHA-256 of the report
    verification_code: str  # The public verification string
    registry_timestamp: str  # When it was added to registry
    status: str = "active"  # active, revoked, expired
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class SafetyRegistry:
    """VERITY Safety Registry - Public Ledger for AI Certifications.
    
    This is the core of the "AI Auditor" credibility system.
    Every certification is recorded here, creating a permanent audit trail.
    
    MVP Implementation: JSON file-based ledger
    Future: Could be migrated to blockchain or distributed database
    """
    
    def __init__(self, registry_path: str | Path = "registry/VERITY_registry.json"):
        """Initialize the registry.
        
        Args:
            registry_path: Path to the JSON ledger file
        """
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing registry or create new
        if self.registry_path.exists():
            with open(self.registry_path, 'r', encoding='utf-8') as f:
                self.ledger = json.load(f)
        else:
            self.ledger = {
                "version": "1.0.0",
                "created_at": datetime.utcnow().isoformat(),
                "entries": []
            }
            self._save()
    
    def register_certificate(
        self,
        certificate_id: str,
        target_system: str,
        target_model: str,
        assessment_date: str,
        asr: float,
        total_attacks: int,
        content_hash: str,
        verification_code: str,
    ) -> RegistryEntry:
        """Register a new certificate in the public ledger.
        
        This is called after a certification is completed.
        It creates a permanent, public record.
        
        Args:
            certificate_id: Unique certificate UUID
            target_system: Name of the AI system
            target_model: LLM model used
            assessment_date: When the assessment was performed
            asr: Attack Success Rate
            total_attacks: Number of attacks tested
            content_hash: SHA-256 of the report
            verification_code: Public verification string
            
        Returns:
            RegistryEntry that was added
        """
        # Check if already registered
        if self.verify_certificate(certificate_id):
            raise ValueError(f"Certificate {certificate_id} already registered")
        
        # Create new entry
        entry = RegistryEntry(
            certificate_id=certificate_id,
            target_system=target_system,
            target_model=target_model,
            assessment_date=assessment_date,
            asr=asr,
            total_attacks=total_attacks,
            content_hash=content_hash,
            verification_code=verification_code,
            registry_timestamp=datetime.utcnow().isoformat(),
            status="active"
        )
        
        # Add to ledger
        self.ledger["entries"].append(entry.to_dict())
        self._save()
        
        return entry
    
    def verify_certificate(self, certificate_id: str) -> Optional[RegistryEntry]:
        """Verify if a certificate exists in the registry.
        
        This is the public verification endpoint.
        Anyone can check if a certificate is legitimate.
        
        Args:
            certificate_id: The certificate UUID to verify
            
        Returns:
            RegistryEntry if found and active, None otherwise
        """
        for entry_dict in self.ledger["entries"]:
            if entry_dict["certificate_id"] == certificate_id:
                # Only return if status is active
                if entry_dict.get("status", "active") == "active":
                    return RegistryEntry(**entry_dict)
                else:
                    return None
        return None
    
    def verify_by_code(self, verification_code: str) -> Optional[RegistryEntry]:
        """Verify a certificate by its verification code.
        
        This is the user-friendly verification method.
        Users can just enter the code from the certificate footer.
        
        Args:
            verification_code: The VERITY-CERT-XXXX-YYYY code
            
        Returns:
            RegistryEntry if found and active, None otherwise
        """
        for entry_dict in self.ledger["entries"]:
            if entry_dict["verification_code"] == verification_code:
                if entry_dict.get("status", "active") == "active":
                    return RegistryEntry(**entry_dict)
                else:
                    return None
        return None
    
    def revoke_certificate(self, certificate_id: str, reason: str = "revoked") -> bool:
        """Revoke a certificate (e.g., if system was modified).
        
        This doesn't delete the entry, just marks it as revoked.
        Maintains audit trail.
        
        Args:
            certificate_id: Certificate to revoke
            reason: Reason for revocation
            
        Returns:
            True if revoked, False if not found
        """
        for entry_dict in self.ledger["entries"]:
            if entry_dict["certificate_id"] == certificate_id:
                entry_dict["status"] = "revoked"
                entry_dict["revocation_reason"] = reason
                entry_dict["revoked_at"] = datetime.utcnow().isoformat()
                self._save()
                return True
        return False
    
    def list_all_certified_systems(self, active_only: bool = True) -> list[RegistryEntry]:
        """Get a list of all certified systems.
        
        This could power a public directory on the VERITY website.
        
        Args:
            active_only: If True, only return active certifications
            
        Returns:
            List of RegistryEntry objects
        """
        entries = []
        for entry_dict in self.ledger["entries"]:
            if active_only and entry_dict.get("status", "active") != "active":
                continue
            entries.append(RegistryEntry(**entry_dict))
        
        # Sort by registry timestamp (newest first)
        entries.sort(key=lambda e: e.registry_timestamp, reverse=True)
        return entries
    
    def get_statistics(self) -> dict:
        """Get registry statistics.
        
        Useful for marketing ("500+ AI systems certified")
        
        Returns:
            Dictionary with stats
        """
        total = len(self.ledger["entries"])
        active = sum(1 for e in self.ledger["entries"] if e.get("status", "active") == "active")
        revoked = sum(1 for e in self.ledger["entries"] if e.get("status") == "revoked")
        
        # Average ASR of certified systems
        asrs = [e["asr"] for e in self.ledger["entries"] if e.get("status", "active") == "active"]
        avg_asr = sum(asrs) / len(asrs) if asrs else 0.0
        
        return {
            "total_certifications": total,
            "active_certifications": active,
            "revoked_certifications": revoked,
            "average_asr": avg_asr,
            "registry_version": self.ledger["version"],
            "registry_created": self.ledger["created_at"]
        }
    
    def export_public_ledger(self, output_path: str | Path) -> Path:
        """Export the public ledger for transparency.
        
        This can be published on GitHub or a public website.
        
        Args:
            output_path: Where to save the public ledger
            
        Returns:
            Path to exported file
        """
        output_path = Path(output_path)
        
        # Create a sanitized version (no sensitive data)
        public_ledger = {
            "version": self.ledger["version"],
            "created_at": self.ledger["created_at"],
            "last_updated": datetime.utcnow().isoformat(),
            "entries": [
                {
                    "certificate_id": e["certificate_id"],
                    "target_system": e["target_system"],
                    "assessment_date": e["assessment_date"],
                    "asr": e["asr"],
                    "verification_code": e["verification_code"],
                    "registry_timestamp": e["registry_timestamp"],
                    "status": e.get("status", "active")
                }
                for e in self.ledger["entries"]
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(public_ledger, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def _save(self):
        """Save the ledger to disk."""
        with open(self.registry_path, 'w', encoding='utf-8') as f:
            json.dump(self.ledger, f, indent=2, ensure_ascii=False)
