"""
Architecture Diff Service - Compares architecture snapshots to detect changes.
Provides detailed change analysis for incremental threat modeling.
"""
import hashlib
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class ComponentChange:
    """Represents a change to a single component."""
    component_id: str
    component_name: str
    component_type: str
    change_type: str  # 'added', 'removed', 'modified'
    old_data: Optional[Dict] = None
    new_data: Optional[Dict] = None
    changed_fields: List[str] = field(default_factory=list)


@dataclass
class FlowChange:
    """Represents a change to a data flow."""
    flow_id: str
    source_id: str
    target_id: str
    change_type: str  # 'added', 'removed', 'modified'
    old_data: Optional[Dict] = None
    new_data: Optional[Dict] = None
    changed_fields: List[str] = field(default_factory=list)


@dataclass
class BoundaryChange:
    """Represents a change to a trust boundary."""
    boundary_id: str
    boundary_name: str
    change_type: str  # 'added', 'removed', 'modified'
    old_data: Optional[Dict] = None
    new_data: Optional[Dict] = None
    changed_fields: List[str] = field(default_factory=list)


@dataclass
class ArchitectureDiff:
    """Complete diff between two architecture versions."""
    # Component changes
    added_components: List[ComponentChange] = field(default_factory=list)
    removed_components: List[ComponentChange] = field(default_factory=list)
    modified_components: List[ComponentChange] = field(default_factory=list)

    # Flow changes
    added_flows: List[FlowChange] = field(default_factory=list)
    removed_flows: List[FlowChange] = field(default_factory=list)
    modified_flows: List[FlowChange] = field(default_factory=list)

    # Trust boundary changes
    added_boundaries: List[BoundaryChange] = field(default_factory=list)
    removed_boundaries: List[BoundaryChange] = field(default_factory=list)
    modified_boundaries: List[BoundaryChange] = field(default_factory=list)

    # Overall metrics
    impact_score: float = 0.0  # 0-1 indicating magnitude of change
    has_security_relevant_changes: bool = False

    def is_empty(self) -> bool:
        """Check if there are no changes."""
        return (
            not self.added_components and
            not self.removed_components and
            not self.modified_components and
            not self.added_flows and
            not self.removed_flows and
            not self.modified_flows and
            not self.added_boundaries and
            not self.removed_boundaries and
            not self.modified_boundaries
        )

    def get_affected_component_ids(self) -> Set[str]:
        """Get all component IDs affected by changes."""
        ids = set()

        for c in self.added_components + self.removed_components + self.modified_components:
            ids.add(c.component_id)

        # Also include components connected by changed flows
        for f in self.added_flows + self.removed_flows + self.modified_flows:
            ids.add(f.source_id)
            ids.add(f.target_id)

        return ids

    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert to a summary dictionary for storage."""
        return {
            "added_components": [c.component_id for c in self.added_components],
            "removed_components": [c.component_id for c in self.removed_components],
            "modified_components": [c.component_id for c in self.modified_components],
            "added_flows": [f.flow_id for f in self.added_flows],
            "removed_flows": [f.flow_id for f in self.removed_flows],
            "modified_flows": [f.flow_id for f in self.modified_flows],
            "added_boundaries": [b.boundary_id for b in self.added_boundaries],
            "removed_boundaries": [b.boundary_id for b in self.removed_boundaries],
            "modified_boundaries": [b.boundary_id for b in self.modified_boundaries],
            "impact_score": self.impact_score,
            "has_security_relevant_changes": self.has_security_relevant_changes,
            "total_changes": self.total_change_count()
        }

    def total_change_count(self) -> int:
        """Get total number of changes."""
        return (
            len(self.added_components) + len(self.removed_components) + len(self.modified_components) +
            len(self.added_flows) + len(self.removed_flows) + len(self.modified_flows) +
            len(self.added_boundaries) + len(self.removed_boundaries) + len(self.modified_boundaries)
        )

    def generate_description(self) -> str:
        """Generate human-readable change description."""
        parts = []

        if self.added_components:
            names = [c.component_name for c in self.added_components[:3]]
            if len(self.added_components) > 3:
                names.append(f"+{len(self.added_components) - 3} more")
            parts.append(f"Added {len(self.added_components)} component(s): {', '.join(names)}")

        if self.removed_components:
            names = [c.component_name for c in self.removed_components[:3]]
            if len(self.removed_components) > 3:
                names.append(f"+{len(self.removed_components) - 3} more")
            parts.append(f"Removed {len(self.removed_components)} component(s): {', '.join(names)}")

        if self.modified_components:
            names = [c.component_name for c in self.modified_components[:3]]
            if len(self.modified_components) > 3:
                names.append(f"+{len(self.modified_components) - 3} more")
            parts.append(f"Modified {len(self.modified_components)} component(s): {', '.join(names)}")

        if self.added_flows:
            parts.append(f"Added {len(self.added_flows)} data flow(s)")
        if self.removed_flows:
            parts.append(f"Removed {len(self.removed_flows)} data flow(s)")
        if self.modified_flows:
            parts.append(f"Modified {len(self.modified_flows)} data flow(s)")

        if self.added_boundaries:
            parts.append(f"Added {len(self.added_boundaries)} trust boundary(ies)")
        if self.removed_boundaries:
            parts.append(f"Removed {len(self.removed_boundaries)} trust boundary(ies)")
        if self.modified_boundaries:
            parts.append(f"Modified {len(self.modified_boundaries)} trust boundary(ies)")

        return "; ".join(parts) if parts else "No changes detected"


class ArchitectureDiffService:
    """Service for computing differences between architecture versions."""

    # Fields that affect security and should flag security-relevant changes
    SECURITY_RELEVANT_FIELDS = {
        'authentication', 'authorization', 'encryption', 'data_classification',
        'security_controls', 'trust_level', 'exposed_to_internet', 'handles_pii',
        'handles_credentials', 'protocol', 'tls_required', 'data_sensitivity'
    }

    # Weights for impact score calculation
    CHANGE_WEIGHTS = {
        'added_component': 0.15,
        'removed_component': 0.10,
        'modified_component': 0.08,
        'added_flow': 0.12,
        'removed_flow': 0.08,
        'modified_flow': 0.06,
        'added_boundary': 0.10,
        'removed_boundary': 0.10,
        'modified_boundary': 0.05,
        'security_field_change': 0.20,
    }

    def compute_hash(self, architecture: Dict[str, Any]) -> str:
        """Generate a stable hash for an architecture snapshot.

        The hash is normalized to ensure consistent comparison regardless
        of JSON key ordering.
        """
        # Normalize by sorting keys recursively
        normalized = json.dumps(architecture, sort_keys=True, default=str)
        return hashlib.sha256(normalized.encode()).hexdigest()

    def compute_diff(
        self,
        old_arch: Optional[Dict[str, Any]],
        new_arch: Dict[str, Any]
    ) -> ArchitectureDiff:
        """Compare two architecture snapshots and compute differences.

        Args:
            old_arch: Previous architecture (None for first version)
            new_arch: New architecture

        Returns:
            ArchitectureDiff with all changes
        """
        diff = ArchitectureDiff()

        if old_arch is None:
            # First version - everything is "added"
            diff = self._build_initial_diff(new_arch)
        else:
            # Compare components
            self._diff_components(old_arch, new_arch, diff)

            # Compare data flows
            self._diff_flows(old_arch, new_arch, diff)

            # Compare trust boundaries
            self._diff_boundaries(old_arch, new_arch, diff)

        # Calculate impact score
        diff.impact_score = self._calculate_impact_score(diff)

        # Check for security-relevant changes
        diff.has_security_relevant_changes = self._has_security_changes(diff)

        return diff

    def _build_initial_diff(self, architecture: Dict[str, Any]) -> ArchitectureDiff:
        """Build diff for initial architecture (everything is new)."""
        diff = ArchitectureDiff()

        # All components are added
        components = architecture.get('components', [])
        for comp in components:
            diff.added_components.append(ComponentChange(
                component_id=comp.get('id', ''),
                component_name=comp.get('name', 'Unknown'),
                component_type=comp.get('type', 'unknown'),
                change_type='added',
                new_data=comp
            ))

        # All flows are added
        flows = architecture.get('data_flows', [])
        for flow in flows:
            diff.added_flows.append(FlowChange(
                flow_id=flow.get('id', f"{flow.get('source', '')}->{flow.get('target', '')}"),
                source_id=flow.get('source', ''),
                target_id=flow.get('target', ''),
                change_type='added',
                new_data=flow
            ))

        # All boundaries are added
        boundaries = architecture.get('trust_boundaries', [])
        for boundary in boundaries:
            diff.added_boundaries.append(BoundaryChange(
                boundary_id=boundary.get('id', ''),
                boundary_name=boundary.get('name', 'Unknown'),
                change_type='added',
                new_data=boundary
            ))

        return diff

    def _diff_components(
        self,
        old_arch: Dict[str, Any],
        new_arch: Dict[str, Any],
        diff: ArchitectureDiff
    ) -> None:
        """Compare components between versions."""
        old_components = {c.get('id'): c for c in old_arch.get('components', [])}
        new_components = {c.get('id'): c for c in new_arch.get('components', [])}

        old_ids = set(old_components.keys())
        new_ids = set(new_components.keys())

        # Added components
        for comp_id in new_ids - old_ids:
            comp = new_components[comp_id]
            diff.added_components.append(ComponentChange(
                component_id=comp_id,
                component_name=comp.get('name', 'Unknown'),
                component_type=comp.get('type', 'unknown'),
                change_type='added',
                new_data=comp
            ))

        # Removed components
        for comp_id in old_ids - new_ids:
            comp = old_components[comp_id]
            diff.removed_components.append(ComponentChange(
                component_id=comp_id,
                component_name=comp.get('name', 'Unknown'),
                component_type=comp.get('type', 'unknown'),
                change_type='removed',
                old_data=comp
            ))

        # Modified components
        for comp_id in old_ids & new_ids:
            old_comp = old_components[comp_id]
            new_comp = new_components[comp_id]
            changed_fields = self._find_changed_fields(old_comp, new_comp)

            if changed_fields:
                diff.modified_components.append(ComponentChange(
                    component_id=comp_id,
                    component_name=new_comp.get('name', 'Unknown'),
                    component_type=new_comp.get('type', 'unknown'),
                    change_type='modified',
                    old_data=old_comp,
                    new_data=new_comp,
                    changed_fields=changed_fields
                ))

    def _diff_flows(
        self,
        old_arch: Dict[str, Any],
        new_arch: Dict[str, Any],
        diff: ArchitectureDiff
    ) -> None:
        """Compare data flows between versions."""
        def flow_key(flow: Dict) -> str:
            return f"{flow.get('source', '')}->{flow.get('target', '')}"

        old_flows = {flow_key(f): f for f in old_arch.get('data_flows', [])}
        new_flows = {flow_key(f): f for f in new_arch.get('data_flows', [])}

        old_keys = set(old_flows.keys())
        new_keys = set(new_flows.keys())

        # Added flows
        for key in new_keys - old_keys:
            flow = new_flows[key]
            diff.added_flows.append(FlowChange(
                flow_id=flow.get('id', key),
                source_id=flow.get('source', ''),
                target_id=flow.get('target', ''),
                change_type='added',
                new_data=flow
            ))

        # Removed flows
        for key in old_keys - new_keys:
            flow = old_flows[key]
            diff.removed_flows.append(FlowChange(
                flow_id=flow.get('id', key),
                source_id=flow.get('source', ''),
                target_id=flow.get('target', ''),
                change_type='removed',
                old_data=flow
            ))

        # Modified flows
        for key in old_keys & new_keys:
            old_flow = old_flows[key]
            new_flow = new_flows[key]
            changed_fields = self._find_changed_fields(old_flow, new_flow)

            if changed_fields:
                diff.modified_flows.append(FlowChange(
                    flow_id=new_flow.get('id', key),
                    source_id=new_flow.get('source', ''),
                    target_id=new_flow.get('target', ''),
                    change_type='modified',
                    old_data=old_flow,
                    new_data=new_flow,
                    changed_fields=changed_fields
                ))

    def _diff_boundaries(
        self,
        old_arch: Dict[str, Any],
        new_arch: Dict[str, Any],
        diff: ArchitectureDiff
    ) -> None:
        """Compare trust boundaries between versions."""
        old_boundaries = {b.get('id'): b for b in old_arch.get('trust_boundaries', [])}
        new_boundaries = {b.get('id'): b for b in new_arch.get('trust_boundaries', [])}

        old_ids = set(old_boundaries.keys())
        new_ids = set(new_boundaries.keys())

        # Added boundaries
        for bound_id in new_ids - old_ids:
            boundary = new_boundaries[bound_id]
            diff.added_boundaries.append(BoundaryChange(
                boundary_id=bound_id,
                boundary_name=boundary.get('name', 'Unknown'),
                change_type='added',
                new_data=boundary
            ))

        # Removed boundaries
        for bound_id in old_ids - new_ids:
            boundary = old_boundaries[bound_id]
            diff.removed_boundaries.append(BoundaryChange(
                boundary_id=bound_id,
                boundary_name=boundary.get('name', 'Unknown'),
                change_type='removed',
                old_data=boundary
            ))

        # Modified boundaries
        for bound_id in old_ids & new_ids:
            old_bound = old_boundaries[bound_id]
            new_bound = new_boundaries[bound_id]
            changed_fields = self._find_changed_fields(old_bound, new_bound)

            if changed_fields:
                diff.modified_boundaries.append(BoundaryChange(
                    boundary_id=bound_id,
                    boundary_name=new_bound.get('name', 'Unknown'),
                    change_type='modified',
                    old_data=old_bound,
                    new_data=new_bound,
                    changed_fields=changed_fields
                ))

    def _find_changed_fields(
        self,
        old_data: Dict[str, Any],
        new_data: Dict[str, Any]
    ) -> List[str]:
        """Find fields that changed between old and new data."""
        changed = []
        all_keys = set(old_data.keys()) | set(new_data.keys())

        for key in all_keys:
            old_val = old_data.get(key)
            new_val = new_data.get(key)

            # Normalize for comparison
            if isinstance(old_val, (list, dict)):
                old_val = json.dumps(old_val, sort_keys=True)
            if isinstance(new_val, (list, dict)):
                new_val = json.dumps(new_val, sort_keys=True)

            if old_val != new_val:
                changed.append(key)

        return changed

    def _calculate_impact_score(self, diff: ArchitectureDiff) -> float:
        """Calculate overall impact score (0-1) for the changes."""
        score = 0.0

        score += len(diff.added_components) * self.CHANGE_WEIGHTS['added_component']
        score += len(diff.removed_components) * self.CHANGE_WEIGHTS['removed_component']
        score += len(diff.modified_components) * self.CHANGE_WEIGHTS['modified_component']
        score += len(diff.added_flows) * self.CHANGE_WEIGHTS['added_flow']
        score += len(diff.removed_flows) * self.CHANGE_WEIGHTS['removed_flow']
        score += len(diff.modified_flows) * self.CHANGE_WEIGHTS['modified_flow']
        score += len(diff.added_boundaries) * self.CHANGE_WEIGHTS['added_boundary']
        score += len(diff.removed_boundaries) * self.CHANGE_WEIGHTS['removed_boundary']
        score += len(diff.modified_boundaries) * self.CHANGE_WEIGHTS['modified_boundary']

        # Bonus for security-relevant field changes
        for comp in diff.modified_components:
            security_changes = set(comp.changed_fields) & self.SECURITY_RELEVANT_FIELDS
            score += len(security_changes) * self.CHANGE_WEIGHTS['security_field_change']

        for flow in diff.modified_flows:
            security_changes = set(flow.changed_fields) & self.SECURITY_RELEVANT_FIELDS
            score += len(security_changes) * self.CHANGE_WEIGHTS['security_field_change']

        # Clamp to 0-1
        return min(1.0, score)

    def _has_security_changes(self, diff: ArchitectureDiff) -> bool:
        """Check if any changes affect security-relevant fields."""
        # Any added/removed component or boundary is security-relevant
        if diff.added_components or diff.removed_components:
            return True
        if diff.added_boundaries or diff.removed_boundaries:
            return True

        # Check modified items for security field changes
        for comp in diff.modified_components:
            if set(comp.changed_fields) & self.SECURITY_RELEVANT_FIELDS:
                return True

        for flow in diff.modified_flows:
            if set(flow.changed_fields) & self.SECURITY_RELEVANT_FIELDS:
                return True

        for boundary in diff.modified_boundaries:
            if set(boundary.changed_fields) & self.SECURITY_RELEVANT_FIELDS:
                return True

        return False

    def identify_affected_threats(
        self,
        diff: ArchitectureDiff,
        existing_threats: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Identify which existing threats are affected by architecture changes.

        Args:
            diff: The architecture diff
            existing_threats: List of existing threat dictionaries

        Returns:
            Dict with keys 'affected', 'unaffected', 'orphaned'
        """
        affected_ids = diff.get_affected_component_ids()

        result = {
            'affected': [],      # Threats related to changed components
            'unaffected': [],    # Threats not affected by changes
            'orphaned': []       # Threats whose components were removed
        }

        removed_component_ids = {c.component_id for c in diff.removed_components}

        for threat in existing_threats:
            threat_components = set(threat.get('affected_components', []))
            target_component = threat.get('target_component')
            if target_component:
                threat_components.add(target_component)

            # Check if threat's components were removed
            if threat_components & removed_component_ids:
                result['orphaned'].append(threat)
            # Check if threat's components were modified
            elif threat_components & affected_ids:
                result['affected'].append(threat)
            else:
                result['unaffected'].append(threat)

        return result
