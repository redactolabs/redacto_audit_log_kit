# Structured audit event schema for logging
from datetime import datetime
# Model for audit log entry
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    organization_uuid: Optional[str] = None
    workspace_uuid: Optional[str] = None
    vrm_vendor_id: Optional[str] = None
    service_name: Optional[str] = None
    action: Optional[str] = None
    crud: Optional[str] = None
    source_ip: Optional[str] = None
    actor_name: Optional[str] = None
    actor_uuid: Optional[str] = None
    resource_name: Optional[str] = None
    resource_uuid: Optional[str] = None
    resource_type: Optional[str] = None
    description: Optional[str] = None
    created: Optional[int] = None  # Unix epoch ns
    # Optionally add more fields as needed

class SearchQuery(BaseModel):
    organization_uuid: Optional[str] = None  # label
    workspace_uuid: Optional[str] = None  
    vrm_vendor_id: Optional[str] = None  # label
    service_name: Optional[str] = None  #label
    action: Optional[str] = None #label
    actor_uuid: Optional[str] = None
    actor_name: Optional[str] = None #label
    resource_uuid: Optional[str] = None 
    resource_name: Optional[str] = None #label
    resource_type: Optional[str] = None  
    crud: Optional[str] = None #label
    source_ip: Optional[str] = None 
    description: Optional[str] = None


    # Loki query_range parameters
    # query: Optional[str] = None
    limit: Optional[int] = 100
    start: Optional[int] = None
    end: Optional[int] = None
    since: Optional[str] = None
    interval: Optional[str] = None
    direction: Optional[str] = None





    #  group_name: Optional[str] = None # what is this?

    #<module>_<field> format for custom fields
    # vrm_vendor_id: Optional[str] = None # label
    # vrm_vendor_domain_name: Optional[str] = None # label


  
# class AuditLogEntry(BaseModel):
# 	timestamp: int  # uint64
# 	trace_id: str   # hex string
# 	span_id: str    # hex string
# 	trace_flags: int
# 	severity_text: str
# 	severity_number: int
# 	attributes: Optional[Dict[str, Any]]
# 	resources: Optional[Dict[str, Any]]
# 	body: str

# class AuditLogEntry(BaseModel):
#     action: str
#     group: Group
#     crud: str
#     created: datetime
#     source_ip: str
#     actor: Actor
#     target: Target
#     description: str	
    
# class Group(SecureSchema):
#     id: str
#     name: str


# class Actor(SecureSchema):
#     id: str
#     name: str


# class Target(SecureSchema):
#     id: str
#     name: str
#     type: str
#     fields: dict[str, str]

