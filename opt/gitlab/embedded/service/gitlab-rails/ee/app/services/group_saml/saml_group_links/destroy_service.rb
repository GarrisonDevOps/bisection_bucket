# frozen_string_literal: true

module GroupSaml
  module SamlGroupLinks
    class DestroyService < BaseService
      def initialize(current_user:, group:, saml_group_link:)
        @current_user = current_user
        @group = group
        @saml_group_link = saml_group_link
      end

      def execute
        return ServiceResponse.error(message: 'Unauthorized') unless authorized?

        destroy_saml_group_link
      end

      def destroy_saml_group_link
        saml_group_link.destroy!
        create_audit_event
        cleanup_scim_group_memberships
        ServiceResponse.success
      rescue ActiveRecord::RecordNotDestroyed
        ServiceResponse.error(message: "Failed to delete SamlGroupLink record", reason: :bad_request)
      end

      private

      attr_reader :current_user, :group, :saml_group_link

      def authorized?
        can?(current_user, :admin_saml_group_links, group)
      end

      def create_audit_event
        ::Gitlab::Audit::Auditor.audit(
          name: 'saml_group_links_removed',
          author: current_user,
          scope: group,
          target: group,
          message: "SAML group links removed. Group Name - #{saml_group_link.saml_group_name}"
        )
      end

      def cleanup_scim_group_memberships
        scim_group_uid = saml_group_link.scim_group_uid
        return if scim_group_uid.blank?
        return if saml_links_exist_for_scim_group?(scim_group_uid)

        ::Authn::CleanupScimGroupMembershipsWorker.perform_async(scim_group_uid)
      end

      def saml_links_exist_for_scim_group?(scim_group_uid)
        SamlGroupLink.by_scim_group_uid(scim_group_uid).exists?
      end
    end
  end
end
