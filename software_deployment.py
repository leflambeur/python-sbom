#pylint:disable=missing-function-docstring      # docstrings
# pylint:disable=missing-module-docstring      # docstrings
# pylint:disable=missing-class-docstring      # docstrings
from typing import Optional

# pylint:disable=unused-import      # To prevent cyclical import errors forward referencing is used
# pylint:disable=cyclic-import      # but pylint doesn't understand this feature

from archivist import archivist as type_helper


class SoftwareDeployment:
    def __init__(self, arch: "type_helper.Archivist"):
        self._arch = arch
        self._asset = None
        self._attachments = None
        self._environment

    @property
    def arch(self):
        return self._arch

    @property
    def asset(self):
        return self._asset

    @property
    def attachments(self):
        return self._attachments

    @property
    def environment(self):
        return self._environment

    # Installation Event
    def installation(
        self,
        sbom_installation: dict,
        *,
        attachments: Optional[list] = None,
        custom_attrs: Optional [dict] = None,
        custom_asset_attrs: Optional [dict] = None,
        ):

        if sbom_installation["environment"] is not None:
            self._environment = sbom_installation["environment"]
        else:
            sbom_installation["environment"] = self._environment

        self._add_attachments(attachments)

        props = {
            "operation": "Record",
            "behaviour": "RecordEvidence",
        }
        attrs = {
            "arc_description": sbom_installation["description"],
            "arc_evidence": "Installation",
            "arc_display_type": "Installation",
            "sbom_installation_component": sbom_installation["name"],
            "sbom_installation_hash": sbom_installation["hash"],
            "sbom_installation_version": sbom_installation["version"],
            "sbom_installation_author": sbom_installation["author"],
            "sbom_installation_supplier": sbom_installation["supplier"],
            "sbom_installation_uuid": sbom_installation["uuid"],
            "sbom_installation_environment": sbom_installation["environment"],
            "arc_attachments": [
                {
                    "arc_display_name": sbom_installation["description"],
                    "arc_attachment_identity": attachment["identity"],
                    "arc_hash_value": attachment["hash"]["value"],
                    "arc_hash_alg": attachment["hash"]["alg"],
                }
                for attachment in self._attachments
            ],

        } 
        if custom_attrs is not None:
            attrs.update(custom_attrs)
        asset_attrs = {
            "arc_display_name": sbom_installation["name"],
            "sbom_version": sbom_installation["version"],
            "sbom_component": sbom_installation["name"],
            "sbom_hash": sbom_installation["hash"],
            "sbom_version": sbom_installation["version"],
            "sbom_author": sbom_installation["author"],
            "sbom_supplier": sbom_installation["supplier"],
            "sbom_uuid": sbom_installation["uuid"],
            "sbom_environment": sbom_installation["environment"]
        }
        if custom_asset_attrs is not None:
            asset_attrs.update(custom_asset_attrs)

        return self.arch.events.create(self._asset["identity"], props=props, attrs=attrs, asset_attrs=asset_attrs, confirm=True)

    def decommission(
        self,
        sbom_decomission: dict,
        *,
        attachments: Optional[list] = None,
        custom_attrs: Optional[dict] = None,
        custom_asset_attrs: Optional[dict] = None,
        ):

        if sbom_decomission["environment"] is not None:
            self._environment = sbom_decomission["environment"]
        else:
            sbom_decomission["environment"] = self._environment

        self._add_attachments(attachments)

        props = {
            "operation": "Record",
            "behaviour": "RecordEvidence",
        }
        attrs = {
            "arc_description": sbom_decomission["description"],
            "arc_evidence": "Decomission",
            "arc_display_type": "Decomission",
            "sbom_decomission_component": sbom_decomission["name"],
            "sbom_decomission_version": sbom_decomission["version"],
            "sbom_decomission_author": sbom_decomission["author"],
            "sbom_decomission_supplier": sbom_decomission["supplier"],
            "sbom_decomission_uuid": sbom_decomission["uuid"],
            "sbom_decomission_target_date": sbom_decomission["target_date"],
            "sbom_decomission_status": sbom_decomission["status"],
            "sbom_decomission_environment": sbom_decomission["environment"],
            "arc_attachments": [
                {
                    "arc_display_name": sbom_decomission["description"],
                    "arc_attachment_identity": attachment["identity"],
                    "arc_hash_value": attachment["hash"]["value"],
                    "arc_hash_alg": attachment["hash"]["alg"],
                }
                for attachment in self._attachments
            ],

        }
        if custom_attrs is not None:
            attrs.update(custom_attrs)
        asset_attrs = {
            "sbom_decomission_target_date": sbom_decomission["target_date"],
            "sbom_decomission_status": sbom_decomission["status"],
            "sbom_environment": sbom_decomission["environment"],
        }
        if custom_asset_attrs is not None:
            asset_attrs.update(custom_asset_attrs)

        return self.arch.events.create(self._asset["identity"], props=props, attrs=attrs, asset_attrs=asset_attrs)

    # Update Events
    def upgrade(
        self,
        sbom_upgrade: dict,
        *,
        attachments: Optional[list] = None,
        custom_attrs: Optional[dict] = None,
        custom_asset_attrs: Optional[dict] = None,
        ):

        if sbom_upgrade["environment"] is not None:
            self._environment = sbom_upgrade["environment"]
        else:
            sbom_upgrade["environment"] = self._environment

        self._add_attachments(attachments)

        props = {
            "operation": "Record",
            "behaviour": "RecordEvidence",
        }
        attrs = {
            "arc_description": sbom_upgrade["description"],
            "arc_evidence": "Update",
            "arc_display_type": "Update",
            "sbom_upgrade_component": sbom_upgrade["name"],
            "sbom_upgrade_hash": sbom_upgrade["hash"],
            "sbom_upgrade_version": sbom_upgrade["version"],
            "sbom_upgrade_author": sbom_upgrade["author"],
            "sbom_upgrade_supplier": sbom_upgrade["supplier"],
            "sbom_upgrade_uuid": sbom_upgrade["uuid"],
            "sbom_upgrade_environment": sbom_upgrade["environment"],
            "arc_attachments": [
                {
                    "arc_display_name": sbom_upgrade["description"],
                    "arc_attachment_identity": attachment["identity"],
                    "arc_hash_value": attachment["hash"]["value"],
                    "arc_hash_alg": attachment["hash"]["alg"],
                }
                for attachment in self._attachments
            ],

        } 
        if custom_attrs is not None:
            attrs.update(custom_attrs)
        asset_attrs = {
            "arc_display_name": sbom_upgrade["name"],
            "sbom_version": sbom_upgrade["version"],
            "sbom_component": sbom_upgrade["name"],
            "sbom_hash": sbom_upgrade["hash"],
            "sbom_version": sbom_upgrade["version"],
            "sbom_author": sbom_upgrade["author"],
            "sbom_supplier": sbom_upgrade["supplier"],
            "sbom_uuid": sbom_upgrade["uuid"],
        }
        if custom_asset_attrs is not None:
            asset_attrs.update(custom_asset_attrs)

        return self.arch.events.create(self._asset["identity"], props=props, attrs=attrs, asset_attrs=asset_attrs, confirm=True)

    def upgrade_plan(
        self,
        sbom_planned: dict,
        *,
        attachments: Optional[list] = None,
        custom_attrs: Optional[dict] = None,
        ):

        if sbom_planned["environment"] is not None:
            self._environment = sbom_planned["environment"]
        else:
            sbom_planned["environment"] = self._environment

        self._add_attachments(attachments)

        props = {
            "operation": "Record",
            "behaviour": "RecordEvidence",
        }
        attrs = {
            "arc_description": sbom_planned["description"],
            "arc_evidence": "Upgrade Plan",
            "arc_display_type": "Upgrade Plan",
            "sbom_planned_date": sbom_planned["date"],
            "sbom_planned_captain": sbom_planned["captain"],
            "sbom_planned_component": sbom_planned["name"],
            "sbom_planned_version": sbom_planned["version"],
            "sbom_planned_reference": sbom_planned["reference"],
            "sbom_planned_environment": sbom_planned["environment"],
            "arc_attachments": [
                {
                    "arc_display_name": sbom_planned["description"],
                    "arc_attachment_identity": attachment["identity"],
                    "arc_hash_value": attachment["hash"]["value"],
                    "arc_hash_alg": attachment["hash"]["alg"],
                }
                for attachment in attachments
            ]
        }
        if custom_attrs is not None:
            attrs.update(custom_attrs)
        return self.arch.events.create(self._asset["identity"], props=props, attrs=attrs, confirm=True)

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
    def _add_attachments(self, attachments: list):
        self._attachments = []
        for attachment in attachments:
            with open(f"{attachment}", "rb") as fd:
                self._attachments.append(self.arch.attachments.upload(fd))


if __name__ == "__main__":
    main()