"""
Threat Lifecycle Service - Manages threat status classification and tracking.
Determines whether threats are new, existing, modified, or resolved.
"""
import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from services.architecture_diff_service import ArchitectureDiff


@dataclass
class ThreatUpdate:
    """Represents a threat with its lifecycle status."""
    threat_id: str
    status: str  # 'new', 'existing', 'modified', 'resolved'
    threat_data: Dict[str, Any]
    change_reason: Optional[str] = None
    affected_components: List[str] = field(default_factory=list)
    previous_data: Optional[Dict[str, Any]] = None


@dataclass
class ThreatClassificationResult:
    """Result of classifying threats against architecture changes."""
    new_threats: List[ThreatUpdate] = field(default_factory=list)
    existing_threats: List[ThreatUpdate] = field(default_factory=list)
    modified_threats: List[ThreatUpdate] = field(default_factory=list)
    resolved_threats: List[ThreatUpdate] = field(default_factory=list)

    def to_dict(self) -> Dict[str, List[Dict]]:
        """Convert to dictionary for serialization."""
        return {
            'new': [{'threat_id': t.threat_id, 'status': t.status, 'threat_data': t.threat_data,
                     'change_reason': t.change_reason, 'affected_components': t.affected_components}
                    for t in self.new_threats],
            'existing': [{'threat_id': t.threat_id, 'status': t.status, 'threat_data': t.threat_data,
                          'affected_components': t.affected_components}
                         for t in self.existing_threats],
            'modified': [{'threat_id': t.threat_id, 'status': t.status, 'threat_data': t.threat_data,
                          'change_reason': t.change_reason, 'affected_components': t.affected_components,
                          'previous_data': t.previous_data}
                         for t in self.modified_threats],
            'resolved': [{'threat_id': t.threat_id, 'status': t.status, 'threat_data': t.threat_data,
                          'change_reason': t.change_reason, 'affected_components': t.affected_components}
                         for t in self.resolved_threats],
        }

    def all_threats(self) -> List[ThreatUpdate]:
        """Get all threats in a single list."""
        return self.new_threats + self.existing_threats + self.modified_threats + self.resolved_threats

    def summary(self) -> Dict[str, int]:
        """Get count summary."""
        return {
            'new': len(self.new_threats),
            'existing': len(self.existing_threats),
            'modified': len(self.modified_threats),
            'resolved': len(self.resolved_threats),
            'total': len(self.all_threats())
        }


class ThreatLifecycleService:
    """Service for managing threat lifecycle and status classification."""

    def generate_stable_threat_id(self, threat: Dict[str, Any]) -> str:
        """Generate a consistent ID for tracking a threat across versions.

        The ID is based on:
        - STRIDE category
        - Target component (or flow endpoints)
        - Attack vector/type

        This ensures the same logical threat gets the same ID even if
        description text changes slightly.
        """
        # Extract key identifying attributes
        stride_category = threat.get('stride_category', threat.get('category', 'unknown'))
        target = threat.get('target_component', threat.get('target', ''))
        attack_vector = threat.get('attack_vector', threat.get('type', ''))

        # For flow-based threats, include source and target
        source = threat.get('source_component', '')
        if source:
            target = f"{source}->{target}"

        # Create a stable identifier
        id_parts = [
            stride_category.lower(),
            target.lower() if isinstance(target, str) else str(target),
            attack_vector.lower() if isinstance(attack_vector, str) else str(attack_vector)
        ]

        # Hash for consistent length
        id_string = "|".join(id_parts)
        hash_suffix = hashlib.md5(id_string.encode()).hexdigest()[:8]

        # Human-readable prefix + hash
        prefix = stride_category[:4].upper() if stride_category else "UNKN"
        return f"{prefix}_{hash_suffix}"

    def classify_threats(
        self,
        existing_threats: List[Dict[str, Any]],
        new_threats: List[Dict[str, Any]],
        diff: ArchitectureDiff
    ) -> ThreatClassificationResult:
        """Classify threats based on architecture changes.

        Args:
            existing_threats: Threats from previous version
            new_threats: Newly generated threats for changed components
            diff: Architecture diff showing what changed

        Returns:
            ThreatClassificationResult with categorized threats
        """
        result = ThreatClassificationResult()

        # Build lookup maps
        existing_by_id = {}
        for threat in existing_threats:
            threat_id = threat.get('threat_id') or self.generate_stable_threat_id(threat)
            existing_by_id[threat_id] = threat

        new_by_id = {}
        for threat in new_threats:
            threat_id = threat.get('threat_id') or self.generate_stable_threat_id(threat)
            new_by_id[threat_id] = threat

        # Get affected component IDs from diff
        affected_component_ids = diff.get_affected_component_ids()
        removed_component_ids = {c.component_id for c in diff.removed_components}

        # Process existing threats
        for threat_id, threat in existing_by_id.items():
            threat_components = self._get_threat_components(threat)

            if threat_id in new_by_id:
                # Threat exists in both - check if modified
                new_threat = new_by_id[threat_id]
                if self._threat_content_changed(threat, new_threat):
                    # Modified - content changed
                    result.modified_threats.append(ThreatUpdate(
                        threat_id=threat_id,
                        status='modified',
                        threat_data=new_threat,
                        change_reason=self._generate_modification_reason(threat, new_threat, diff),
                        affected_components=list(threat_components),
                        previous_data=threat
                    ))
                else:
                    # Existing - no change
                    result.existing_threats.append(ThreatUpdate(
                        threat_id=threat_id,
                        status='existing',
                        threat_data=threat,
                        affected_components=list(threat_components)
                    ))
            elif threat_components & removed_component_ids:
                # Component was removed - threat is resolved
                result.resolved_threats.append(ThreatUpdate(
                    threat_id=threat_id,
                    status='resolved',
                    threat_data=threat,
                    change_reason=f"Component(s) removed: {', '.join(threat_components & removed_component_ids)}",
                    affected_components=list(threat_components)
                ))
            elif threat_components & affected_component_ids:
                # Component was modified but threat still applies - check new threats
                # If not regenerated, keep as existing
                result.existing_threats.append(ThreatUpdate(
                    threat_id=threat_id,
                    status='existing',
                    threat_data=threat,
                    affected_components=list(threat_components)
                ))
            else:
                # Unaffected component - keep as existing
                result.existing_threats.append(ThreatUpdate(
                    threat_id=threat_id,
                    status='existing',
                    threat_data=threat,
                    affected_components=list(threat_components)
                ))

        # Process new threats not in existing
        for threat_id, threat in new_by_id.items():
            if threat_id not in existing_by_id:
                threat_components = self._get_threat_components(threat)
                result.new_threats.append(ThreatUpdate(
                    threat_id=threat_id,
                    status='new',
                    threat_data=threat,
                    change_reason=self._generate_new_threat_reason(threat, diff),
                    affected_components=list(threat_components)
                ))

        return result

    def _get_threat_components(self, threat: Dict[str, Any]) -> set:
        """Extract component IDs associated with a threat."""
        components = set()

        if threat.get('target_component'):
            components.add(threat['target_component'])
        if threat.get('source_component'):
            components.add(threat['source_component'])
        if threat.get('affected_components'):
            components.update(threat['affected_components'])
        if threat.get('component_id'):
            components.add(threat['component_id'])

        return components

    def _threat_content_changed(
        self,
        old_threat: Dict[str, Any],
        new_threat: Dict[str, Any]
    ) -> bool:
        """Check if threat content has meaningfully changed."""
        # Fields to compare for changes
        compare_fields = [
            'severity', 'risk_score', 'likelihood', 'impact',
            'mitigations', 'attack_vector', 'prerequisites',
            'affected_assets', 'data_at_risk'
        ]

        for field in compare_fields:
            old_val = old_threat.get(field)
            new_val = new_threat.get(field)

            # Normalize for comparison
            if isinstance(old_val, (list, dict)):
                old_val = json.dumps(old_val, sort_keys=True)
            if isinstance(new_val, (list, dict)):
                new_val = json.dumps(new_val, sort_keys=True)

            if old_val != new_val:
                return True

        return False

    def _generate_modification_reason(
        self,
        old_threat: Dict[str, Any],
        new_threat: Dict[str, Any],
        diff: ArchitectureDiff
    ) -> str:
        """Generate human-readable reason for threat modification."""
        reasons = []

        # Check severity change
        old_sev = old_threat.get('severity')
        new_sev = new_threat.get('severity')
        if old_sev != new_sev:
            reasons.append(f"Severity changed from {old_sev} to {new_sev}")

        # Check risk score change
        old_risk = old_threat.get('risk_score')
        new_risk = new_threat.get('risk_score')
        if old_risk != new_risk:
            reasons.append(f"Risk score changed from {old_risk} to {new_risk}")

        # Check component changes
        threat_components = self._get_threat_components(new_threat)
        modified_comp_ids = {c.component_id for c in diff.modified_components}
        affected = threat_components & modified_comp_ids
        if affected:
            reasons.append(f"Related component(s) modified: {', '.join(affected)}")

        if not reasons:
            reasons.append("Threat details updated based on architecture changes")

        return "; ".join(reasons)

    def _generate_new_threat_reason(
        self,
        threat: Dict[str, Any],
        diff: ArchitectureDiff
    ) -> str:
        """Generate reason for why a new threat was identified."""
        threat_components = self._get_threat_components(threat)

        # Check if related to added components
        added_comp_ids = {c.component_id for c in diff.added_components}
        related_added = threat_components & added_comp_ids
        if related_added:
            return f"New component(s) added: {', '.join(related_added)}"

        # Check if related to added flows
        added_flow_components = set()
        for flow in diff.added_flows:
            added_flow_components.add(flow.source_id)
            added_flow_components.add(flow.target_id)
        related_flows = threat_components & added_flow_components
        if related_flows:
            return f"New data flow(s) involving: {', '.join(related_flows)}"

        # Check if related to added boundaries
        if diff.added_boundaries:
            return "New trust boundary introduced"

        return "Identified during incremental analysis"

    def merge_threat_results(
        self,
        classification: ThreatClassificationResult
    ) -> List[Dict[str, Any]]:
        """Merge classified threats into a single list with status annotations.

        Returns threats suitable for storage/display, with status field added.
        """
        merged = []

        for threat_update in classification.all_threats():
            threat = threat_update.threat_data.copy()
            threat['threat_id'] = threat_update.threat_id
            threat['lifecycle_status'] = threat_update.status
            threat['change_reason'] = threat_update.change_reason
            threat['affected_components'] = threat_update.affected_components

            if threat_update.previous_data:
                threat['previous_version'] = threat_update.previous_data

            merged.append(threat)

        return merged

    def get_threat_timeline(
        self,
        threat_history_records: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Build a timeline view for a specific threat.

        Args:
            threat_history_records: List of ThreatHistory records for one threat_id

        Returns:
            Chronologically ordered list of threat states with context
        """
        # Sort by created_at
        sorted_records = sorted(
            threat_history_records,
            key=lambda x: x.get('created_at', datetime.min)
        )

        timeline = []
        for i, record in enumerate(sorted_records):
            entry = {
                'version': i + 1,
                'status': record.get('status'),
                'timestamp': record.get('created_at'),
                'architecture_version_id': record.get('architecture_version_id'),
                'change_reason': record.get('change_reason'),
                'threat_data': record.get('threat_data'),
            }

            # Add transition info
            if i > 0:
                prev_record = sorted_records[i - 1]
                entry['previous_status'] = prev_record.get('status')
                entry['transition'] = f"{prev_record.get('status')} → {record.get('status')}"

            timeline.append(entry)

        return timeline
