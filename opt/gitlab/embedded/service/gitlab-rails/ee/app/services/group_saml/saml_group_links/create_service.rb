# frozen_string_literal: true

module GroupSaml
  module SamlGroupLinks
    class CreateService < BaseService
      def initialize(current_user:, group:, params:)
        @current_user = current_user
        @group = group
        @params = params
        @saml_group_link = group.saml_group_links.new
      end

      def execute
        return ServiceResponse.error(message: 'Unauthorized') unless authorized?

        save_saml_group_link
      end

      def save_saml_group_link
        saml_group_link.assign_attributes(params)
        saml_group_link.saml_group_name = saml_group_link.saml_group_name&.strip
        saml_group_link.set_access_level_based_on_member_role
        inherit_scim_group_uid
        saml_group_link.save ? success : error
      rescue ArgumentError => e
        saml_group_link.errors.add(:base, e.message)
        error
      end

      attr_reader :saml_group_link

      private

      attr_reader :current_user, :group, :params

      def authorized?
        can?(current_user, :admin_saml_group_links, group)
      end

      def success
        create_audit_event
        ServiceResponse.success
      end

      def error
        ServiceResponse.error(message: 'Failed to create SamlGroupLink',
          payload: { error: saml_group_link.errors.full_messages.join(",") },
          http_status: 400)
      end

      def create_audit_event
        message = 'SAML group links created. Group Name - %{group_name}, '\
                  'Access Level - %{access_level}' % { group_name: saml_group_link.saml_group_name,
                                                       access_level: saml_group_link.access_level }

        if saml_group_link.member_role_id
          message << (', Member Role - %{member_role_id}' % { member_role_id: saml_group_link.member_role_id })
        end

        message << (', Assign Duo Seats') if saml_group_link.assign_duo_seats?

        ::Gitlab::Audit::Auditor.audit(
          name: 'saml_group_links_created',
          author: current_user,
          scope: group,
          target: group,
          message: message
        )
      end

      def inherit_scim_group_uid
        return if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return if saml_group_link.saml_group_name.blank?

        existing_scim_group_uid = SamlGroupLink
          .by_saml_group_name(saml_group_link.saml_group_name)
          .with_scim_group_uid
          .pick(:scim_group_uid)

        saml_group_link.scim_group_uid = existing_scim_group_uid if existing_scim_group_uid
      end
    end
  end
end
