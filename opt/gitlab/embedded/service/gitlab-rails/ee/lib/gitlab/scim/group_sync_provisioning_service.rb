# frozen_string_literal: true

module Gitlab
  module Scim
    class GroupSyncProvisioningService < BaseProvisioningService
      def execute
        return error_response(errors: ["Missing params: #{missing_params}"]) unless missing_params.empty?
        return error_response(errors: ["Invalid UUID for scim_group_uid"]) unless valid_scim_group_uid?

        if matching_group_links.exists?
          update_group_links
          success_response
        else
          error_response(errors: ["No matching SAML group found with name: #{@parsed_hash[:saml_group_name]}"])
        end
      end

      private

      def update_group_links
        matching_group_links.update_all(scim_group_uid: @parsed_hash[:scim_group_uid])
      end

      def matching_group_links
        @matching_group_links ||= SamlGroupLink.by_saml_group_name(@parsed_hash[:saml_group_name])
      end

      def group_link
        matching_group_links.first
      end
      strong_memoize_attr :group_link

      def success_response
        ::Gitlab::Scim::ProvisioningResponse.new(status: :success, group_link: group_link)
      end

      def missing_params
        required_params = [:saml_group_name, :scim_group_uid]
        required_params.select { |param| @parsed_hash[param].blank? }
      end

      def valid_scim_group_uid?
        uuid_param = @parsed_hash[:scim_group_uid]

        return false unless uuid_param.is_a?(String)

        # UUID format: 8-4-4-4-12 hex digits
        uuid_regex = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i
        uuid_regex.match?(uuid_param)
      end
    end
  end
end
