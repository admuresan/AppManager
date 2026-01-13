"""
OCI (Oracle Cloud Infrastructure) utility for managing security list rules
"""
import oci
import os
import json
from pathlib import Path
from typing import Optional, Tuple, List, Dict
import logging

logger = logging.getLogger(__name__)

class OCIManager:
    """Manager for OCI security list operations"""
    
    def __init__(self):
        self.config = None
        self.network_client = None
        self.compartment_id = None
        self.vcn_id = None
        self._load_config()
    
    def _load_config(self):
        """Load OCI configuration"""
        # First try instance folder JSON config
        instance_path = Path(__file__).parent.parent.parent / 'instance'
        oci_json_config = instance_path / 'oci_config.json'
        
        # Also check standard OCI config location
        oci_config_path = Path.home() / '.oci' / 'config'
        
        config_loaded = False
        
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
                    
                    self.config = oci.config.from_dict(oci_config_dict)
                    self.compartment_id = config_data.get('compartment_id')
                    self.vcn_id = config_data.get('vcn_id')
                    config_loaded = True
            except Exception as e:
                logger.warning(f"Failed to load OCI JSON config: {e}")
        
        # Fall back to standard OCI config file
        if not config_loaded and oci_config_path.exists():
            try:
                self.config = oci.config.from_file(str(oci_config_path))
                config_loaded = True
            except Exception as e:
                logger.warning(f"Failed to load OCI config file: {e}")
        
        if config_loaded:
            try:
                # Initialize network client
                self.network_client = oci.core.VirtualNetworkClient(self.config)
                logger.info("OCI configuration loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize OCI client: {e}")
                self.config = None
                self.network_client = None
        else:
            logger.debug("OCI config file not found or incomplete, OCI features disabled")
            self.config = None
            self.network_client = None
    
    def is_configured(self) -> bool:
        """Check if OCI is properly configured"""
        return self.config is not None and self.network_client is not None
    
    def get_security_lists(self, compartment_id: str, vcn_id: str) -> List[Dict]:
        """Get all security lists for a VCN"""
        if not self.is_configured():
            return []
        
        try:
            response = self.network_client.list_security_lists(
                compartment_id=compartment_id,
                vcn_id=vcn_id
            )
            return [sl.data for sl in response.data]
        except Exception as e:
            logger.error(f"Failed to get security lists: {e}")
            return []
    
    def get_default_security_list(self, compartment_id: str, vcn_id: str) -> Optional[str]:
        """Get the default security list ID for a VCN"""
        security_lists = self.get_security_lists(compartment_id, vcn_id)
        
        for sl in security_lists:
            if sl.display_name == "Default Security List for VCN" or sl.is_default:
                return sl.id
        
        # If no default found, return the first one
        if security_lists:
            return security_lists[0].id
        
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
            # Get current security list
            get_response = self.network_client.get_security_list(security_list_id)
            security_list = get_response.data
            
            # Check if rule already exists
            for rule in security_list.ingress_security_rules:
                if (hasattr(rule, 'tcp_options') and rule.tcp_options and
                    hasattr(rule.tcp_options, 'destination_port_range') and
                    rule.tcp_options.destination_port_range):
                    port_range = rule.tcp_options.destination_port_range
                    if (port_range.min == port and port_range.max == port and
                        rule.source == source and rule.protocol == protocol):
                        return True, f"Rule already exists for port {port}"
            
            # Create new ingress rule
            new_rule = oci.core.models.IngressSecurityRule(
                protocol=protocol,
                source=source,
                description=description or f"Allow {protocol} traffic on port {port}",
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(
                        min=port,
                        max=port
                    )
                ) if protocol == "TCP" else None,
                udp_options=oci.core.models.UdpOptions(
                    destination_port_range=oci.core.models.PortRange(
                        min=port,
                        max=port
                    )
                ) if protocol == "UDP" else None
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
            
            return True, f"Added OCI ingress rule for port {port}"
            
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
            # Get current security list
            get_response = self.network_client.get_security_list(security_list_id)
            security_list = get_response.data
            
            # Filter out the rule to remove
            updated_rules = []
            removed = False
            
            for rule in security_list.ingress_security_rules:
                should_keep = True
                
                if rule.protocol == protocol and rule.source == source:
                    if protocol == "TCP" and hasattr(rule, 'tcp_options') and rule.tcp_options:
                        port_range = rule.tcp_options.destination_port_range
                        if port_range and port_range.min == port and port_range.max == port:
                            should_keep = False
                            removed = True
                    elif protocol == "UDP" and hasattr(rule, 'udp_options') and rule.udp_options:
                        port_range = rule.udp_options.destination_port_range
                        if port_range and port_range.min == port and port_range.max == port:
                            should_keep = False
                            removed = True
                
                if should_keep:
                    updated_rules.append(rule)
            
            if not removed:
                return True, f"No rule found for port {port} to remove"
            
            # Update security list
            update_details = oci.core.models.UpdateSecurityListDetails(
                ingress_security_rules=updated_rules
            )
            
            self.network_client.update_security_list(
                security_list_id=security_list_id,
                update_security_list_details=update_details
            )
            
            return True, f"Removed OCI ingress rule for port {port}"
            
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
        Configure a port in OCI security list
        
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
        
        # Try to get VCN and compartment from instance if not provided
        if not security_list_id:
            # Use instance values if available
            compartment_id = compartment_id or self.compartment_id
            vcn_id = vcn_id or self.vcn_id
            
            if compartment_id and vcn_id:
                security_list_id = self.get_default_security_list(compartment_id, vcn_id)
        
        if not security_list_id:
            return False, "Could not determine security list ID. Please configure compartment_id and vcn_id."
        
        if action == "allow":
            return self.add_ingress_rule(security_list_id, port)
        elif action == "remove":
            return self.remove_ingress_rule(security_list_id, port)
        else:
            return False, f"Unknown action: {action}"


# Global instance
_oci_manager = None

def get_oci_manager() -> OCIManager:
    """Get or create OCI manager instance"""
    global _oci_manager
    if _oci_manager is None:
        _oci_manager = OCIManager()
    return _oci_manager

def is_oci_configured() -> bool:
    """Check if OCI is configured"""
    return get_oci_manager().is_configured()

def configure_oci_port(port: int, action: str = "allow", **kwargs) -> Tuple[bool, str]:
    """Configure a port in OCI security list"""
    manager = get_oci_manager()
    if not manager.is_configured():
        return False, "OCI not configured"
    
    return manager.configure_port(port, action, **kwargs)

