# frozen_string_literal: true

module SoftwareLicensePolicies
  class CreateService < ::BaseService
    def initialize(project, user, params)
      super(project, user, params.with_indifferent_access)
    end

    def execute
      result = create_for_scan_result_policy
      success(software_license_policy: result)
    rescue ActiveRecord::RecordInvalid => exception
      error(exception.record.errors.full_messages, 400)
    end

    private

    def create_for_scan_result_policy
      catalogue_license = find_software_license_in_catalogue(params[:name])

      if catalogue_license
        create_software_license_policies_with_software_license(catalogue_license)
      else
        create_software_license_policies_with_custom_software_license(find_or_create_custom_software_license)
      end
    end

    def create_software_license_policies_with_software_license(catalogue_license)
      project.software_license_policies.create!(
        classification: params[:approval_status],
        scan_result_policy_read: params[:scan_result_policy_read],
        approval_policy_rule_id: params[:approval_policy_rule_id],
        software_license_spdx_identifier: catalogue_license&.spdx_identifier
      )
    end

    def create_software_license_policies_with_custom_software_license(custom_software_license)
      project.software_license_policies.create!(
        classification: params[:approval_status],
        custom_software_license: custom_software_license,
        scan_result_policy_read: params[:scan_result_policy_read],
        approval_policy_rule_id: params[:approval_policy_rule_id]
      )
    end

    def find_or_create_custom_software_license
      response = Security::CustomSoftwareLicenses::FindOrCreateService.new(project: project,
        params: params).execute

      response.payload[:custom_software_license]
    end

    def find_software_license_in_catalogue(name)
      Gitlab::SPDX::Catalogue
        .latest_active_licenses
        .find { |license| license.name == name }
    end
  end
end
