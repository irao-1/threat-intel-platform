"""
Abstract base class for sandbox collectors.
"""

from abc import ABC, abstractmethod
from typing import Dict


class SandboxCollector(ABC):
    """Abstract base class for all sandbox providers."""
    
    @abstractmethod
    def get_analysis(self, task_id: str) -> Dict:
        """
        Fetch analysis from sandbox.
        
        Returns standardized dict with threat indicators.
        """
        pass
    
    @staticmethod
    def standardize_analysis(raw_data: Dict) -> Dict:
        """Ensure analysis has all required fields with defaults."""
        return {
            'task_id': raw_data.get('task_id'),
            'file': raw_data.get('file', {}),
            'verdict': raw_data.get('verdict', 'unknown'),
            'c2_domains': raw_data.get('c2_domains', []),
            'c2_ips': raw_data.get('c2_ips', []),
            'dropped_files': raw_data.get('dropped_files', []),
            'download_urls': raw_data.get('download_urls', []),
            'processes': raw_data.get('processes', []),
            'network_connections': raw_data.get('network_connections', []),
            'registry_modifications': raw_data.get('registry_modifications', []),
            'mitre_techniques': raw_data.get('mitre_techniques', [])
        }
