"""
OCI (Oracle Cloud Infrastructure) utility for managing security list rules.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import oci
import os
import json
from pathlib import Path
from typing import Optional, Tuple, List, Dict
import logging
import requests

logger = logging.getLogger(__name__)

class OCIManager:
    """Manager for OCI security list operations"""
    
    def __init__(self):
        self.config = None
        self.network_client = None
        self.compartment_id = None
        self.vcn_id = None
        self.config_source = None
        self.last_error = None
        self.last_metadata = {
            "ok": None,
            "url": None,
            "status_code": None,
            "error": None,
        }
        self._load_config()

    def _load_ocid_hints(self) -> Dict[str, Optional[str]]:
        """
        Load compartment_id / vcn_id hints from multiple places.

        This allows OCI API auth to come from ~/.oci/config while IDs come from:
        - instance/oci_config.json (preferred)
        - oci_ssh/OCID_config.json (deploy-time source)
        - environment variables
        """
        hints: Dict[str, Optional[str]] = {
            "compartment_id": None,
            "vcn_id": None,
            "region": None,
        }

        # Env vars first (highest priority)
        hints["compartment_id"] = os.environ.get("OCI_COMPARTMENT_ID") or os.environ.get("COMPARTMENT_ID")
        hints["vcn_id"] = os.environ.get("OCI_VCN_ID") or os.environ.get("VCN_ID")
        hints["region"] = os.environ.get("OCI_REGION") or os.environ.get("REGION")

        # instance/oci_config.json (may exist even if auth comes from ~/.oci/config)
        try:
            instance_path = Path(__file__).parent.parent.parent / "instance"
            oci_json_config = instance_path / "oci_config.json"
            if oci_json_config.exists():
                with open(oci_json_config, "r") as f:
                    cfg = json.load(f) or {}
                hints["compartment_id"] = hints["compartment_id"] or cfg.get("compartment_id")
                hints["vcn_id"] = hints["vcn_id"] or cfg.get("vcn_id")
                hints["region"] = hints["region"] or cfg.get("region")
        except Exception:
            pass

        # oci_ssh/OCID_config.json (repo file used by deploy.sh)
        try:
            repo_root = Path(__file__).parent.parent.parent
            ocid_cfg_path = repo_root / "oci_ssh" / "OCID_config.json"
            if ocid_cfg_path.exists():
                with open(ocid_cfg_path, "r") as f:
                    ocid_cfg = json.load(f) or {}
                hints["compartment_id"] = hints["compartment_id"] or ocid_cfg.get("COMPARTMENT_OCID_PLACEHOLDER")
                hints["vcn_id"] = hints["vcn_id"] or ocid_cfg.get("VCN_OCID_PLACEHOLDER")
                hints["region"] = hints["region"] or ocid_cfg.get("REGION_PLACEHOLDER")
        except Exception:
            pass

        return hints
    
    def _load_config(self):
        """Load OCI configuration"""
        # First try instance folder JSON config
        instance_path = Path(__file__).parent.parent.parent / 'instance'
        oci_json_config = instance_path / 'oci_config.json'
        
        # Also check standard OCI config location
        oci_config_path = Path.home() / '.oci' / 'config'
        
        config_loaded = False
        self.config_source = None
        self.last_error = None
        
        # Try JSON config first (has compartment_id and vcn_id)
        if oci_json_config.exists():
            try:
                with open(oci_json_config, 'r') as f:
                    config_data = json.load(f)
                
                # Check if config is complete (not just placeholders)
                if (config_data.get('user') and 
                    'PLACEHOLDER' not in config_data.get('user', '') and
                    config_data.get('tenancy') and
                    'PLACEHOLDER' not in config_data.get('tenancy', '') and
                    config_data.get('fingerprint') and
                    'PLACEHOLDER' not in config_data.get('fingerprint', '')):
                    
                    # Convert JSON config to OCI config dict
                    oci_config_dict = {
                        'user': config_data.get('user'),
                        'fingerprint': config_data.get('fingerprint'),
                        'tenancy': config_data.get('tenancy'),
                        'region': config_data.get('region', 'us-ashburn-1'),
                        'key_file': os.path.expanduser(config_data.get('key_file', '~/.oci/oci_api_key.pem'))
                    }

                    # NOTE: OCI SDK config is a plain dict. Some installed SDK versions
                    # don't provide oci.config.from_dict(), so validate and use the dict directly.
                    try:
                        errors = oci.config.validate_config(oci_config_dict)
                        if errors:
                            raise ValueError(errors)
                    except Exception as e:
                        raise Exception(f"Invalid OCI config in instance/oci_config.json: {e}")

                    self.config = oci_config_dict
                    self.compartment_id = config_data.get('compartment_id')
                    self.vcn_id = config_data.get('vcn_id')
                    config_loaded = True
                    self.config_source = str(oci_json_config)
            except Exception as e:
                self.last_error = f"Failed to load instance/oci_config.json: {e}"
                logger.warning(self.last_error)
        
        # Fall back to standard OCI config file
        if not config_loaded and oci_config_path.exists():
            try:
                cfg = oci.config.from_file(str(oci_config_path))

                # Treat placeholder configs as "not configured" to avoid confusing failures later.
                try:
                    suspect = []
                    for k in ("user", "tenancy", "fingerprint", "region", "key_file"):
                        v = (cfg.get(k) or "")
                        if isinstance(v, str) and "PLACEHOLDER" in v:
                            suspect.append(k)
                    if suspect:
                        raise Exception(f"Config contains placeholders in: {', '.join(suspect)}")

                    errors = oci.config.validate_config(cfg)
                    if errors:
                        raise ValueError(errors)
                except Exception as e:
                    raise Exception(f"Invalid ~/.oci/config: {e}")

                self.config = cfg
                config_loaded = True
                self.config_source = str(oci_config_path)
            except Exception as e:
                self.last_error = f"Failed to load ~/.oci/config: {e}"
                logger.warning(self.last_error)
        
        if config_loaded:
            try:
                # If auth came from ~/.oci/config, we still need compartment_id/vcn_id to manage security lists.
                hints = self._load_ocid_hints()
                self.compartment_id = self.compartment_id or hints.get("compartment_id")
                self.vcn_id = self.vcn_id or hints.get("vcn_id")

                # If region hint exists and config is missing region, set it.
                try:
                    if hints.get("region") and not self.config.get("region"):
                        self.config["region"] = hints["region"]
                except Exception:
                    pass

                # Initialize network client
                self.network_client = oci.core.VirtualNetworkClient(self.config)
                logger.info("OCI configuration loaded successfully")
            except Exception as e:
                # Keep self.config for diagnostics; client is unusable until fixed.
                self.last_error = f"Failed to initialize OCI client: {e}"
                logger.warning(self.last_error)
                self.network_client = None
        else:
            logger.debug("OCI config file not found or incomplete, OCI features disabled")
            self.config = None
            self.network_client = None
            if not self.last_error:
                self.last_error = f"OCI config not found (checked {oci_json_config} and {oci_config_path})"

    @staticmethod
    def _normalize_protocol(protocol: str) -> Tuple[str, str]:
        """
        OCI Security List rule protocol must be a stringified IP protocol number:
        - TCP: "6"
        - UDP: "17"
        - ICMP: "1"
        We accept common aliases ("TCP", "UDP") and normalize.
        """
        p = (protocol or "").strip()
        pu = p.upper()
        if pu in ("TCP", "6", "IPPROTO_TCP"):
            return "6", "TCP"
        if pu in ("UDP", "17", "IPPROTO_UDP"):
            return "17", "UDP"
        if pu in ("ICMP", "1", "IPPROTO_ICMP"):
            return "1", "ICMP"
        # Unknown/unsupported: pass through (may still work for numeric values)
        return p, p

    def _fetch_instance_vnics_metadata(self) -> List[Dict]:
        """
        Best-effort: fetch OCI instance VNIC metadata from the OCI metadata service.

        This is only reachable from within an OCI instance.
        Docs: `http://169.254.169.254/opc/v2/` endpoints.
        """
        self.last_metadata = {"ok": None, "url": None, "status_code": None, "error": None}
        headers = {"Authorization": "Bearer Oracle"}
        url_variants = [
            "http://169.254.169.254/opc/v2/vnics",
            "http://169.254.169.254/opc/v2/vnics/",
            "http://169.254.169.254/opc/v1/vnics",
            "http://169.254.169.254/opc/v1/vnics/",
        ]
        last_err = None
        for url in url_variants:
            for _attempt in range(2):
                try:
                    resp = requests.get(url, headers=headers, timeout=2.0)
                    self.last_metadata["url"] = url
                    self.last_metadata["status_code"] = resp.status_code
                    if resp.status_code != 200:
                        last_err = f"metadata status {resp.status_code}"
                        continue
                    data = resp.json()
                    if isinstance(data, list):
                        self.last_metadata["ok"] = True
                        return list(data or [])
                    last_err = "metadata returned non-list JSON"
                except Exception as e:
                    self.last_metadata["url"] = url
                    last_err = str(e)
                    continue
        self.last_metadata["ok"] = False
        self.last_metadata["error"] = last_err or "metadata unavailable"
        return []

    def _get_instance_network_context(self) -> Dict[str, object]:
        """
        Determine subnet security lists + attached NSGs for the current instance.

        Returns:
            dict with keys:
              - subnet_id (str|None)
              - security_list_ids (list[str])
              - nsg_ids (list[str])
              - public_ip (str|None)
        """
        ctx = {
            "subnet_id": None,
            "security_list_ids": [],
            "nsg_ids": [],
            "public_ip": None,
            "metadata": dict(self.last_metadata or {}),
        }
        if not self.is_configured():
            return ctx

        vnics = self._fetch_instance_vnics_metadata()
        ctx["metadata"] = dict(self.last_metadata or {})
        if not vnics:
            return ctx

        # Prefer the first VNIC (primary). Metadata usually returns primary first.
        v0 = vnics[0] or {}
        subnet_id = v0.get("subnetId") or v0.get("subnet_id")
        public_ip = v0.get("publicIp") or v0.get("public_ip")
        nsg_ids = v0.get("nsgIds") or v0.get("nsg_ids") or []

        ctx["subnet_id"] = subnet_id
        ctx["public_ip"] = public_ip
        try:
            ctx["nsg_ids"] = list(nsg_ids or [])
        except Exception:
            ctx["nsg_ids"] = []

        if subnet_id:
            try:
                subnet = self.network_client.get_subnet(subnet_id).data
                security_list_ids = getattr(subnet, "security_list_ids", None) or []
                ctx["security_list_ids"] = list(security_list_ids or [])
            except Exception as e:
                logger.warning(f"Failed to load subnet security lists for {subnet_id}: {e}")

        return ctx

    def _configure_security_lists(self, security_list_ids: List[str], port: int, action: str) -> Tuple[bool, List[str]]:
        """Apply a port rule to multiple security lists."""
        msgs: List[str] = []
        any_ok = False
        for sl_id in list(security_list_ids or []):
            try:
                if action == "allow":
                    ok, msg = self.add_ingress_rule(sl_id, port)
                elif action == "remove":
                    ok, msg = self.remove_ingress_rule(sl_id, port)
                else:
                    ok, msg = False, f"Unknown action: {action}"
                any_ok = any_ok or bool(ok)
                msgs.append(f"SecurityList {sl_id}: {msg}")
            except Exception as e:
                msgs.append(f"SecurityList {sl_id}: error: {e}")
        return any_ok, msgs

    def _nsg_rule_exists(self, nsg_id: str, port: int, source: str = "0.0.0.0/0", protocol: str = "TCP") -> bool:
        """Check whether an NSG already allows ingress to the given port."""
        try:
            protocol_num, _protocol_label = self._normalize_protocol(protocol)
            rules = self.network_client.list_network_security_group_security_rules(
                network_security_group_id=nsg_id
            ).data or []
            for r in rules:
                if getattr(r, "direction", None) != "INGRESS":
                    continue
                if getattr(r, "protocol", None) != protocol_num:
                    continue
                if getattr(r, "source", None) != source:
                    continue
                tcp_opts = getattr(r, "tcp_options", None)
                if protocol_num == "6" and tcp_opts:
                    pr = getattr(tcp_opts, "destination_port_range", None)
                    if pr and getattr(pr, "min", None) == port and getattr(pr, "max", None) == port:
                        return True
            return False
        except Exception:
            return False

    def _add_nsg_ingress_rule(self, nsg_id: str, port: int, source: str = "0.0.0.0/0", protocol: str = "TCP") -> Tuple[bool, str]:
        """Add an ingress rule to an NSG."""
        if not self.is_configured():
            return False, "OCI not configured"
        try:
            protocol_num, protocol_label = self._normalize_protocol(protocol)
            if self._nsg_rule_exists(nsg_id, port, source=source, protocol=protocol):
                return True, f"Rule already exists for {protocol_label} port {port}"

            rule = oci.core.models.AddSecurityRuleDetails(
                direction="INGRESS",
                protocol=protocol_num,
                source=source,
                description=f"Allow {protocol_label} traffic on port {port}",
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(min=port, max=port)
                ) if protocol_num == "6" else None,
                udp_options=oci.core.models.UdpOptions(
                    destination_port_range=oci.core.models.PortRange(min=port, max=port)
                ) if protocol_num == "17" else None,
            )
            details = oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(security_rules=[rule])
            self.network_client.add_network_security_group_security_rules(
                network_security_group_id=nsg_id,
                add_network_security_group_security_rules_details=details,
            )
            return True, f"Added NSG ingress rule for {protocol_label} port {port}"
        except oci.exceptions.ServiceError as e:
            return False, f"OCI NSG API error: {e.message}"
        except Exception as e:
            return False, f"Failed to add NSG rule: {e}"

    def _configure_nsgs(self, nsg_ids: List[str], port: int, action: str) -> Tuple[bool, List[str]]:
        """Apply a port rule to multiple NSGs (allow supported; remove is best-effort)."""
        msgs: List[str] = []
        any_ok = False
        for nsg_id in list(nsg_ids or []):
            try:
                if action == "allow":
                    ok, msg = self._add_nsg_ingress_rule(nsg_id, port)
                elif action == "remove":
                    ok, msg = False, "Remove not implemented for NSG rules"
                else:
                    ok, msg = False, f"Unknown action: {action}"
                any_ok = any_ok or bool(ok)
                msgs.append(f"NSG {nsg_id}: {msg}")
            except Exception as e:
                msgs.append(f"NSG {nsg_id}: error: {e}")
        return any_ok, msgs
    
    def is_configured(self) -> bool:
        """
        Check if OCI is configured enough for security-list port management.

        Note: we require compartment_id + vcn_id because AppManager calls configure_port()
        without providing a specific security_list_id.
        """
        return (
            self.config is not None
            and self.network_client is not None
            and bool(self.compartment_id)
            and bool(self.vcn_id)
        )
    
    def get_security_lists(self, compartment_id: str, vcn_id: str) -> List[Dict]:
        """Get all security lists for a VCN"""
        if not self.is_configured():
            return []
        
        try:
            response = self.network_client.list_security_lists(
                compartment_id=compartment_id,
                vcn_id=vcn_id
            )
            # OCI SDK returns model objects in response.data
            return list(response.data or [])
        except Exception as e:
            logger.error(f"Failed to get security lists: {e}")
            return []
    
    def get_default_security_list(self, compartment_id: str, vcn_id: str) -> Optional[str]:
        """Get the default security list ID for a VCN"""
        security_lists = self.get_security_lists(compartment_id, vcn_id)
        
        for sl in security_lists:
            try:
                if getattr(sl, "display_name", None) == "Default Security List for VCN" or bool(getattr(sl, "is_default", False)):
                    return getattr(sl, "id", None)
            except Exception:
                continue
        
        # If no default found, return the first one
        if security_lists:
            try:
                return getattr(security_lists[0], "id", None)
            except Exception:
                return None
        
        return None
    
    def add_ingress_rule(
        self,
        security_list_id: str,
        port: int,
        protocol: str = "TCP",
        source: str = "0.0.0.0/0",
        description: str = None
    ) -> Tuple[bool, str]:
        """
        Add an ingress rule to a security list
        
        Args:
            security_list_id: OCID of the security list
            port: Port number to allow
            protocol: Protocol (TCP, UDP, etc.)
            source: Source CIDR block (default: 0.0.0.0/0 for all)
            description: Description for the rule
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.is_configured():
            return False, "OCI not configured"
        
        try:
            protocol_num, protocol_label = self._normalize_protocol(protocol)

            # Get current security list
            get_response = self.network_client.get_security_list(security_list_id)
            security_list = get_response.data
            
            # Check if rule already exists
            for rule in security_list.ingress_security_rules:
                if getattr(rule, "protocol", None) != protocol_num or getattr(rule, "source", None) != source:
                    continue

                if protocol_num == "6" and getattr(rule, "tcp_options", None):
                    port_range = getattr(rule.tcp_options, "destination_port_range", None)
                    if port_range and port_range.min == port and port_range.max == port:
                        return True, f"Rule already exists for {protocol_label} port {port}"
                if protocol_num == "17" and getattr(rule, "udp_options", None):
                    port_range = getattr(rule.udp_options, "destination_port_range", None)
                    if port_range and port_range.min == port and port_range.max == port:
                        return True, f"Rule already exists for {protocol_label} port {port}"
            
            # Create new ingress rule
            new_rule = oci.core.models.IngressSecurityRule(
                protocol=protocol_num,
                source=source,
                description=description or f"Allow {protocol_label} traffic on port {port}",
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(
                        min=port,
                        max=port
                    )
                ) if protocol_num == "6" else None,
                udp_options=oci.core.models.UdpOptions(
                    destination_port_range=oci.core.models.PortRange(
                        min=port,
                        max=port
                    )
                ) if protocol_num == "17" else None
            )
            
            # Add new rule to existing rules
            updated_rules = list(security_list.ingress_security_rules)
            updated_rules.append(new_rule)
            
            # Update security list
            update_details = oci.core.models.UpdateSecurityListDetails(
                ingress_security_rules=updated_rules
            )
            
            self.network_client.update_security_list(
                security_list_id=security_list_id,
                update_security_list_details=update_details
            )
            
            return True, f"Added OCI ingress rule for {protocol_label} port {port}"
            
        except oci.exceptions.ServiceError as e:
            if e.status == 400 and "already exists" in str(e.message).lower():
                return True, f"Rule already exists for port {port}"
            return False, f"OCI API error: {e.message}"
        except Exception as e:
            logger.error(f"Failed to add OCI ingress rule: {e}")
            return False, f"Failed to add OCI rule: {str(e)}"
    
    def remove_ingress_rule(
        self,
        security_list_id: str,
        port: int,
        protocol: str = "TCP",
        source: str = "0.0.0.0/0"
    ) -> Tuple[bool, str]:
        """
        Remove an ingress rule from a security list
        
        Args:
            security_list_id: OCID of the security list
            port: Port number to remove
            protocol: Protocol (TCP, UDP, etc.)
            source: Source CIDR block
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.is_configured():
            return False, "OCI not configured"
        
        try:
            protocol_num, protocol_label = self._normalize_protocol(protocol)

            # Get current security list
            get_response = self.network_client.get_security_list(security_list_id)
            security_list = get_response.data
            
            # Filter out the rule to remove
            updated_rules = []
            removed = False
            
            for rule in security_list.ingress_security_rules:
                should_keep = True
                
                if getattr(rule, "protocol", None) == protocol_num and getattr(rule, "source", None) == source:
                    if protocol_num == "6" and hasattr(rule, 'tcp_options') and rule.tcp_options:
                        port_range = rule.tcp_options.destination_port_range
                        if port_range and port_range.min == port and port_range.max == port:
                            should_keep = False
                            removed = True
                    elif protocol_num == "17" and hasattr(rule, 'udp_options') and rule.udp_options:
                        port_range = rule.udp_options.destination_port_range
                        if port_range and port_range.min == port and port_range.max == port:
                            should_keep = False
                            removed = True
                
                if should_keep:
                    updated_rules.append(rule)
            
            if not removed:
                return True, f"No rule found for {protocol_label} port {port} to remove"
            
            # Update security list
            update_details = oci.core.models.UpdateSecurityListDetails(
                ingress_security_rules=updated_rules
            )
            
            self.network_client.update_security_list(
                security_list_id=security_list_id,
                update_security_list_details=update_details
            )
            
            return True, f"Removed OCI ingress rule for {protocol_label} port {port}"
            
        except Exception as e:
            logger.error(f"Failed to remove OCI ingress rule: {e}")
            return False, f"Failed to remove OCI rule: {str(e)}"
    
    def configure_port(
        self,
        port: int,
        action: str = "allow",
        compartment_id: str = None,
        vcn_id: str = None,
        security_list_id: str = None
    ) -> Tuple[bool, str]:
        """
        Configure a port in OCI networking.

        Prefer the current instance subnet security lists + attached NSGs (if detectable),
        otherwise fall back to the VCN default security list.
        
        Args:
            port: Port number
            action: 'allow' to add rule, 'remove' to delete rule
            compartment_id: OCID of compartment (optional, will try to detect)
            vcn_id: OCID of VCN (optional, will try to detect)
            security_list_id: OCID of security list (optional, will use default)
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.is_configured():
            return False, "OCI not configured"

        # Use instance values if available
        compartment_id = compartment_id or self.compartment_id
        vcn_id = vcn_id or self.vcn_id

        # If explicitly targeting a single security list, keep old behavior.
        if security_list_id:
            if action == "allow":
                return self.add_ingress_rule(security_list_id, port)
            if action == "remove":
                return self.remove_ingress_rule(security_list_id, port)
            return False, f"Unknown action: {action}"

        # Best-effort: configure the actual instance network controls (subnet SLs + attached NSGs)
        ctx = self._get_instance_network_context()
        sl_ids = list(ctx.get("security_list_ids") or [])
        nsg_ids = list(ctx.get("nsg_ids") or [])

        msgs: List[str] = []
        ok_any = False

        if sl_ids:
            ok_sl, sl_msgs = self._configure_security_lists(sl_ids, port=port, action=action)
            ok_any = ok_any or ok_sl
            msgs.extend(sl_msgs)
        else:
            # Fall back: apply to ALL security lists in the VCN (more robust than "default").
            if compartment_id and vcn_id:
                all_lists = self.get_security_lists(compartment_id, vcn_id)
                all_ids = []
                for sl in list(all_lists or []):
                    try:
                        sid = getattr(sl, "id", None)
                        if sid:
                            all_ids.append(sid)
                    except Exception:
                        continue
                if all_ids:
                    ok_sl, sl_msgs = self._configure_security_lists(all_ids, port=port, action=action)
                    ok_any = ok_any or ok_sl
                    msgs.extend([m + " (fallback all security lists)" for m in sl_msgs])
                else:
                    msgs.append("No security list IDs found (subnet unknown and VCN lists could not be enumerated)")
            else:
                msgs.append("No security list IDs found (missing compartment_id/vcn_id)")

        if nsg_ids:
            ok_nsg, nsg_msgs = self._configure_nsgs(nsg_ids, port=port, action=action)
            ok_any = ok_any or ok_nsg
            msgs.extend(nsg_msgs)
        else:
            msgs.append("No NSG IDs detected for instance (skipping NSG update)")

        # Emit metadata diagnostics to help troubleshoot when rules are applied but ports still blocked.
        try:
            md = (ctx.get("metadata") or {})
            if md:
                msgs.append(
                    f"Metadata vnics: ok={md.get('ok')} status={md.get('status_code')} url={md.get('url')} err={md.get('error')}"
                )
            if ctx.get("subnet_id") or ctx.get("public_ip"):
                msgs.append(f"Instance network: subnet={ctx.get('subnet_id')} public_ip={ctx.get('public_ip')}")
        except Exception:
            pass

        return bool(ok_any), "; ".join([m for m in msgs if m])


# Global instance
_oci_manager = None

def get_oci_manager() -> OCIManager:
    """Get or create OCI manager instance"""
    global _oci_manager
    if _oci_manager is None:
        _oci_manager = OCIManager()
    return _oci_manager

def reset_oci_manager() -> None:
    """Reset OCI manager singleton (useful after config updates)."""
    global _oci_manager
    _oci_manager = None

def is_oci_configured() -> bool:
    """Check if OCI is configured"""
    return get_oci_manager().is_configured()

def configure_oci_port(port: int, action: str = "allow", **kwargs) -> Tuple[bool, str]:
    """Configure a port in OCI security list"""
    manager = get_oci_manager()
    if not manager.is_configured():
        # In multi-worker environments, each worker has its own singleton.
        # Retry once with a fresh instance to pick up newly saved configs.
        reset_oci_manager()
        manager = get_oci_manager()
    if not manager.is_configured():
        detail = getattr(manager, "last_error", None) or "OCI not configured"
        return False, detail
    
    return manager.configure_port(port, action, **kwargs)

