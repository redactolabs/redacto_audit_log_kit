"""
Organization UUID mappings per service.
Format: {client_name: organization_uuid}

Populate these dictionaries with actual client names and org UUIDs.
"""

VRM_ORGS = {
    "razorpay": "069e0a7d-a09b-4840-bb99-443a992546ab",
    "vivamoney": "94acefc9-422a-45f5-8241-02714e72e663",
    "exotel": "bb594b05-6133-40fb-ab41-1de58128ba17",
    "indifi_capital": "f2407ec5-3ac5-4f9f-9ffd-432374b71412",
    "indifi_technologies": "1f53630d-0126-4fe2-9b23-8188a4767542",
    "oxyzo_finance": "393cedd2-a8d2-45d3-82d9-080d7573f66f",
    "pinelabs": "38a3b273-2546-4270-8109-428257a27066",
    "pinelabs_business_uat": "189cb6fc-0007-4ba3-80e7-dcc19e80ac5c",
    "pinelabs_pay_uat": "d890d9df-25a6-4dfe-9b8e-89c27d6ce855",
    "pinelabs_uat": "cfa67089-f98b-466d-9a84-41b2c4118ffd",
    "motilal_oswal": "50db6473-3f21-40ee-ba84-922130716db5",
}

TC_ORGS = {
    # "client_name": "org-uuid-xxx",
}

CONSENT_ORGS = {
    # "client_name": "org-uuid-xxx",
}

SERVICE_ORG_MAPPING = {
    "vrm": VRM_ORGS,
    "tc": TC_ORGS,
    "consent": CONSENT_ORGS,
}

VALID_SERVICES = list(SERVICE_ORG_MAPPING.keys())
