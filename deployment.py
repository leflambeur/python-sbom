from archivist.archivist import Archivist

# Installation Event
def do_installation(
    arch, 
    asset,
    sbom_name,
    sbom_description,
    sbom_version,
    sbom_hash,
    sbom_author,
    sbom_supplier,
    sbom_uuid,
    sbom_environment,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_description,
        "arc_evidence": "Installation",
        "arc_display_type": "Installation",
        "sbom_installation_component": sbom_name,
        "sbom_installation_hash": sbom_hash,
        "sbom_installation_version": sbom_version,
        "sbom_installation_author": sbom_author,
        "sbom_installation_supplier": sbom_supplier,
        "sbom_installation_uuid": sbom_uuid,
        "sbom_installation_environment": sbom_environment,
        "arc_attachments": [
            {
                "arc_display_name": sbom_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ],

    } 
    attrs.update(custom_attrs)
    asset_attrs = {
        "arc_display_name": sbom_name,
        "sbom_version": sbom_version,
        "sbom_component": sbom_name,
        "sbom_hash": sbom_hash,
        "sbom_version": sbom_version,
        "sbom_author": sbom_author,
        "sbom_supplier": sbom_supplier,
        "sbom_uuid": sbom_uuid,
        "sbom_environment": sbom_environment
    }

    return arch.events.create(asset["identity"], props=props, attrs=attrs, asset_attrs=asset_attrs)

def do_decommission(
    arch, 
    asset,
    sbom_decomission_name,
    sbom_decomission_description,
    sbom_decomission_version,
    sbom_decomission_author,
    sbom_decomission_supplier,
    sbom_decomission_uuid,
    sbom_decomission_target_date,
    sbom_decomission_status,
    sbom_decomission_environment,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_decomission_description,
        "arc_evidence": "Release",
        "arc_display_type": "Release",
        "sbom_decomission_component": sbom_decomission_name,
        "sbom_decomission_version": sbom_decomission_version,
        "sbom_decomission_author": sbom_decomission_author,
        "sbom_decomission_supplier": sbom_decomission_supplier,
        "sbom_decomission_uuid": sbom_decomission_uuid,
        "sbom_decomission_target_date": sbom_decomission_target_date,
        "sbom_decomission_status": sbom_decomission_status,
        "sbom_decomission_environment": sbom_decomission_environment,
        "arc_attachments": [
            {
                "arc_display_name": sbom_decomission_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ],

    } 
    attrs.update(custom_attrs)
    asset_attrs = {
        "sbom_decomission_target_date": sbom_decomission_target_date,
        "sbom_decomission_status": sbom_decomission_status,
        "sbom_environment": sbom_decomission_environment
    }

    return arch.events.create(asset["identity"], props=props, attrs=attrs, asset_attrs=asset_attrs)

# Update Events
def do_upgrade(
    arch, 
    asset,
    sbom_name,
    sbom_description,
    sbom_hash,
    sbom_version,
    sbom_author,
    sbom_supplier,
    sbom_uuid,
    sbom_environment,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_description,
        "arc_evidence": "Update",
        "arc_display_type": "Update",
        "sbom_upgrade_component": sbom_name,
        "sbom_upgrade_hash": sbom_hash,
        "sbom_upgrade_version": sbom_version,
        "sbom_upgrade_author": sbom_author,
        "sbom_upgrade_supplier": sbom_supplier,
        "sbom_upgrade_uuid": sbom_uuid,
        "sbom_upgrade_environment": sbom_environment,
        "arc_attachments": [
            {
                "arc_display_name": sbom_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ],

    } 
    attrs.update(custom_attrs)
    asset_attrs = {
        "arc_display_name": sbom_name,
        "sbom_version": sbom_version,
        "sbom_component": sbom_name,
        "sbom_hash": sbom_hash,
        "sbom_version": sbom_version,
        "sbom_author": sbom_author,
        "sbom_supplier": sbom_supplier,
        "sbom_uuid": sbom_uuid,
    }

    return arch.events.create(asset["identity"], props=props, attrs=attrs, asset_attrs=asset_attrs)

def do_upgrade_plan(
    arch, 
    asset,
    sbom_planned_name,
    sbom_planned_description,
    sbom_planned_version,
    sbom_planned_captain,
    sbom_planned_date,
    sbom_planned_reference,
    sbom_planned_environment,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_planned_description,
        "arc_evidence": "Upgrade Plan",
        "arc_display_type": "Upgrade Plan",
        "sbom_planned_date": sbom_planned_date,
        "sbom_planned_captain": sbom_planned_captain,
        "sbom_planned_component": sbom_planned_name,
        "sbom_planned_version": sbom_planned_version,
        "sbom_planned_reference": sbom_planned_reference,
        "sbom_planned_environment": sbom_planned_environment,
        "arc_attachments": [
            {
                "arc_display_name": sbom_planned_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ]
    }
    attrs.update(custom_attrs)
    return arch.events.create(asset["identity"], props=props, attrs=attrs)

def do_upgrade_accepted(
    arch, 
    asset,
    sbom_accepted_name,
    sbom_accepted_description,
    sbom_accepted_version,
    sbom_accepted_captain,
    sbom_accepted_date,
    sbom_accepted_reference,
    sbom_accepted_environment,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_accepted_description,
        "arc_evidence": "Upgrade Accepted",
        "arc_display_type": "Upgrade Accepted",
        "sbom_accepted_date": sbom_accepted_date,
        "sbom_accepted_captain": sbom_accepted_captain,
        "sbom_accepted_component": sbom_accepted_name,
        "sbom_accepted_version": sbom_accepted_version,
        "sbom_accepted_reference": sbom_accepted_reference,
        "sbom_accepted_environment": sbom_accepted_environment,
        "arc_attachments": [
            {
                "arc_display_name": sbom_accepted_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ]
    }
    attrs.update(custom_attrs)
    return arch.events.create(asset["identity"], props=props, attrs=attrs)

# Rollback Events
def do_rollback(
    arch, 
    asset,
    sbom_name,
    sbom_description,
    sbom_hash,
    sbom_version,
    sbom_author,
    sbom_supplier,
    sbom_uuid,
    sbom_license,
    sbom_vuln_reference,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_description,
        "arc_evidence": "Release",
        "arc_display_type": "Release",
        "sbom_component": sbom_name,
        "sbom_hash": sbom_hash,
        "sbom_version": sbom_version,
        "sbom_author": sbom_author,
        "sbom_supplier": sbom_supplier,
        "sbom_uuid": sbom_uuid,
        "sbom_license": sbom_license,
        "sbom_vuln_reference": sbom_vuln_reference,
        "arc_attachments": [
            {
                "arc_display_name": sbom_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ],

    } 
    attrs.update(custom_attrs)
    asset_attrs = {
        "arc_display_name": sbom_name,
        "sbom_version": sbom_version,
        "sbom_component": sbom_name,
        "sbom_hash": sbom_hash,
        "sbom_version": sbom_version,
        "sbom_author": sbom_author,
        "sbom_supplier": sbom_supplier,
        "sbom_uuid": sbom_uuid,
        "sbom_license": sbom_license
    }

    return arch.events.create(asset["identity"], props=props, attrs=attrs, asset_attrs=asset_attrs)

def do_rollback_plan(
    arch, 
    asset,
    sbom_planned_name,
    sbom_planned_description,
    sbom_planned_version,
    sbom_planned_captain,
    sbom_planned_date,
    sbom_planned_reference,
    sbom_planned_environment,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_planned_description,
        "arc_evidence": "Rollback Plan",
        "arc_display_type": "Rollback Plan",
        "sbom_planned_date": sbom_planned_date,
        "sbom_planned_captain": sbom_planned_captain,
        "sbom_planned_component": sbom_planned_name,
        "sbom_planned_version": sbom_planned_version,
        "sbom_planned_reference": sbom_planned_reference,
        "sbom_planned_environment": sbom_planned_environment,
        "arc_attachments": [
            {
                "arc_display_name": sbom_planned_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ]
    }
    attrs.update(custom_attrs)
    return arch.events.create(asset["identity"], props=props, attrs=attrs)

def do_rollback_accepted(
    arch, 
    asset,
    sbom_accepted_name,
    sbom_accepted_description,
    sbom_accepted_version,
    sbom_accepted_captain,
    sbom_accepted_date,
    sbom_accepted_reference,
    sbom_accepted_environment,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_accepted_description,
        "arc_evidence": "Rollback Accepted",
        "arc_display_type": "Rollback Accepted",
        "sbom_accepted_date": sbom_accepted_date,
        "sbom_accepted_captain": sbom_accepted_captain,
        "sbom_accepted_component": sbom_accepted_name,
        "sbom_accepted_version": sbom_accepted_version,
        "sbom_accepted_reference": sbom_accepted_reference,
        "sbom_accepted_environment": sbom_accepted_environment,
        "arc_attachments": [
            {
                "arc_display_name": sbom_accepted_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ]
    }
    attrs.update(custom_attrs)
    return arch.events.create(asset["identity"], props=props, attrs=attrs)

# Vulnerability Events
def do_vuln_disclosure(
    arch, 
    asset,
    vuln_name,
    vuln_description,
    vuln_reference,
    vuln_id,
    vuln_category,
    vuln_severity,
    vuln_status,
    vuln_author,
    vuln_target_component,
    vuln_target_version,
    attachments
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": vuln_description,
        "arc_evidence": "Vulnerability Disclosure",
        "arc_display_type": "Vulnerability Disclosure",
        "vuln_name": vuln_name,
        "vuln_reference": vuln_reference,
        "vuln_id": vuln_id,
        "vuln_category": vuln_category,
        "vuln_severity": vuln_severity,
        "vuln_status": vuln_status,
        "vuln_author": vuln_author,
        "vuln_target_component": vuln_target_component,
        "vuln_target_version": vuln_target_version,
        "arc_attachments": [
            {
                "arc_display_name": vuln_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ]
    }

    return arch.events.create(asset["identity"], props=props, attrs=attrs)

def do_vuln_update(
    arch, 
    asset,
    vuln_name,
    vuln_description,
    vuln_reference,
    vuln_id,
    vuln_category,
    vuln_severity,
    vuln_status,
    vuln_author,
    vuln_target_component,
    vuln_target_version,
    attachments
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": vuln_description,
        "arc_evidence": "Vulnerability Update",
        "arc_display_type": "Vulnerability Update",
        "vuln_name": vuln_name,
        "vuln_reference": vuln_reference,
        "vuln_id": vuln_id,
        "vuln_category": vuln_category,
        "vuln_severity": vuln_severity,
        "vuln_status": vuln_status,
        "vuln_author": vuln_author,
        "vuln_target_component": vuln_target_component,
        "vuln_target_version": vuln_target_version,
        "arc_attachments": [
            {
                "arc_display_name": vuln_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ]
    }

    return arch.events.create(asset["identity"], props=props, attrs=attrs)

# Create Asset
def create_deployment(
    arch, 
    sbom_name, 
    sbom_description,
    attachments
    ):

    attrs = {
        "arc_display_name": sbom_name,  
        "arc_description": sbom_description,  
        "arc_display_type": "Software Deployment",
        "arc_attachments": [
            {
                "arc_display_name": "arc_primary_image",
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments ]
    }
    behaviours = [
        "Attachments",
        "Firmware",
        "LocationUpdate",
        "Maintenance",
        "RecordEvidence",
    ]

    return arch.assets.create(behaviours, attrs, confirm=True)

# Attachment
def attachment(arch, file):
    with open("attachments/%s" %file, 'rb') as fd:
          return arch.attachments.upload(fd)

def main():
    with open(".auth_token", mode="r") as tokenfile:
        authtoken = tokenfile.read().strip()

    # Initialize connection to Archivist
    arch = Archivist(
        "https://rkvst.poc.jitsuin.io",
        auth=authtoken,
    )
    
    print("Creating Software Deployment Asset...")

    deployment = create_deployment(
        arch,
        "Production ACME Roadrunner Detector 2013 Coyote Edition SP1",
        "Different box, same great taste!",
        [attachment(arch, "Comp_2.jpeg")]
        )

    print("Software Deployment Asset %s Created" %deployment["identity"])

    print("Performing 4.1.5 Installation...")
    
    install_4_1_5 = do_installation(
        arch,
        deployment,
        "ACME Roadrunner Detector 2013 Coyote Edition SP1",
        "v4.1.5 Installation - Production - ACME Roadrunner Detector 2013 Coyote Edition SP1",
        "a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a",
        "v4.1.5",
        "The ACME Corporation",
        "Coyote Services, Inc.",
        "com.acme.rrd2013-ce-sp1-v4-1-5-0",
        "Production",
        [attachment(arch, "v4_1_5_sbom.xml")],
        sbom_license="www.gnu.org/licenses/gpl.txt"
        )
    
    print("4.1.5 Installation Completed")

if __name__ == "__main__":
    main()