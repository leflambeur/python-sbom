
from archivist.archivist import Archivist

# Release Events
def do_release(
    arch, 
    asset,
    sbom_name,
    sbom_description,
    sbom_hash,
    sbom_version,
    sbom_author,
    sbom_supplier,
    sbom_uuid,
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

def do_release_plan(
    arch, 
    asset,
    sbom_planned_name,
    sbom_planned_description,
    sbom_planned_captain,
    sbom_planned_date,
    sbom_planned_version,
    sbom_planned_reference,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_planned_description,
        "arc_evidence": "Release Plan",
        "arc_display_type": "Release Plan",
        "sbom_planned_date": sbom_planned_date,
        "sbom_planned_captain": sbom_planned_captain,
        "sbom_planned_component": sbom_planned_name,
        "sbom_planned_version": sbom_planned_version,
        "sbom_planned_reference": sbom_planned_reference,
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

def do_release_accepted(
    arch, 
    asset,
    sbom_accepted_name,
    sbom_accepted_description,
    sbom_accepted_captain,
    sbom_accepted_date,
    sbom_accepted_version,
    sbom_accepted_approver,
    sbom_accepted_reference,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_accepted_description,
        "arc_evidence": "Release Plan",
        "arc_display_type": "Release Plan",
        "sbom_accepted_date": sbom_accepted_date,
        "sbom_accepted_captain": sbom_accepted_captain,
        "sbom_accepted_component": sbom_accepted_name,
        "sbom_accepted_version": sbom_accepted_version,
        "sbom_accepted_approver": sbom_accepted_approver,
        "sbom_accepted_vuln_reference": sbom_accepted_reference,
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

# Patch Events
def do_patch(
    arch, 
    asset,
    sbom_patch_target_component,
    sbom_patch_description,
    sbom_patch_hash,
    sbom_patch_target_version,
    sbom_patch_author,
    sbom_patch_supplier,
    sbom_patch_uuid,
    sbom_patch_vuln_reference,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_patch_description,
        "arc_evidence": "Patch",
        "arc_display_type": "Patch",
        "sbom_patch_component": sbom_patch_target_component,
        "sbom_patch_hash": sbom_patch_hash,
        "sbom_patch_target_version": sbom_patch_target_version,
        "sbom_patch_author": sbom_patch_author,
        "sbom_patch_supplier": sbom_patch_supplier,
        "sbom_patch_uuid": sbom_patch_uuid,
        "sbom_patch_vuln_reference": sbom_patch_vuln_reference,
        "arc_attachments": [
            {
                "arc_display_name": sbom_patch_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ]
    }
    attrs.update(custom_attrs)
    return arch.events.create(asset["identity"], props=props, attrs=attrs)

def do_private_patch(
    arch, 
    asset,
    sbom_patch_private_id,
    sbom_patch_target_component,
    sbom_patch_description,
    sbom_patch_hash,
    sbom_patch_target_version,
    sbom_patch_author,
    sbom_patch_supplier,
    sbom_patch_uuid,
    sbom_patch_reference,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_patch_description,
        "arc_evidence": "Patch",
        "arc_display_type": "{sbom_patch_private_id}_Patch",
        "sbom_patch_component": sbom_patch_target_component,
        "sbom_patch_hash": sbom_patch_hash,
        "sbom_patch_version": sbom_patch_target_version,
        "sbom_patch_author": sbom_patch_author,
        "sbom_patch_supplier": sbom_patch_supplier,
        "sbom_patch_uuid": sbom_patch_uuid,
        "sbom_patch_vuln_reference": sbom_patch_reference,
        "arc_attachments": [
            {
                "arc_display_name": sbom_patch_description,
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
    attachments,
    **custom_attrs
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
    attrs.update(custom_attrs)
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
    attachments,
    **custom_attrs
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
    attrs.update(custom_attrs)
    return arch.events.create(asset["identity"], props=props, attrs=attrs)

# EOL Deprecatopm Events
def do_deprecation(
    arch, 
    asset,
    sbom_eol_target_component,
    sbom_eol_description,
    sbom_eol_target_version,
    sbom_eol_target_uuid,
    sbom_eol_target_date,
    attachments,
    **custom_attrs
    ):

    props = {
        "operation": "Record",
        "behaviour": "RecordEvidence",
    }
    attrs = {
        "arc_description": sbom_eol_description,
        "arc_evidence": "Deprecation",
        "arc_display_type": "Deprecation",
        "sbom_eol_target_component": sbom_eol_target_component,
        "sbom_eol_target_version": sbom_eol_target_version,
        "sbom_eol_target_uuid": sbom_eol_target_uuid,
        "sbom_eol_target_date": sbom_eol_target_date,
        "arc_attachments": [
            {
                "arc_display_name": sbom_eol_description,
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments
        ]
    }
    attrs.update(custom_attrs)
    return arch.events.create(asset["identity"], props=props, attrs=attrs)

# Asset
def create_package(
    arch, 
    sbom_name, 
    sbom_description,
    attachments,
    **custom_attrs
    ):

    attrs = {
        "arc_display_name": sbom_name,  
        "arc_description": sbom_description,  
        "arc_display_type": "Software Package",
        "arc_attachments": [
            {
                "arc_display_name": "arc_primary_image",
                "arc_attachment_identity": attachment["identity"],
                "arc_hash_value": attachment["hash"]["value"],
                "arc_hash_alg": attachment["hash"]["alg"],
            }
            for attachment in attachments ]
    }
    attrs.update(custom_attrs)
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
    
    print("Creating Software Package Asset...")

    package = create_package(
        arch,
        "ACME Roadrunner Detector 2013 Coyote Edition SP1",
        "Different box, same great taste!",
        [attachment(arch, "Comp_2.jpeg")]
        )

    print("Software Package Asset %s Created" %package["identity"])

    print("Performing Release 4.1.5...")
    
    release_4_1_5 = do_release(
        arch,
        package,
        "ACME Roadrunner Detector 2013 Coyote Edition SP1",
        "v4.1.5 Release - ACME Roadrunner Detector 2013 Coyote Edition SP1",
        "a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a",
        "v4.1.5",
        "The ACME Corporation",
        "Coyote Services, Inc.",
        "com.acme.rrd2013-ce-sp1-v4-1-5-0",
        [attachment(arch, "v4_1_5_sbom.xml")],
        sbom_license="www.gnu.org/licenses/gpl.txt"
        )
    
    print("Release 4.1.5 completed")

if __name__ == "__main__":
    main()