# frozen_string_literal: true

module Gitlab
  module Scim
    class GroupAttributeCheck
      EXTERNAL_ID_ERROR = "Changing the externalId of a group isn't supported"
      SCIM_TYPE = 'mutability'

      def initialize(scim_group_uid:)
        @scim_group_uid = scim_group_uid
      end

      def error_for(display_names:, external_ids:)
        new_name = display_names.compact.find { |name| renamed?(name) }
        return error(rename_error(new_name)) if new_name

        error(EXTERNAL_ID_ERROR) if external_ids.compact.any? { |id| id.to_s != scim_group_uid }
      end

      private

      attr_reader :scim_group_uid

      def renamed?(name)
        saml_group_names.any? && saml_group_names.exclude?(name.to_s)
      end

      def saml_group_names
        @saml_group_names ||= SamlGroupLink.by_scim_group_uid(scim_group_uid).map(&:saml_group_name).uniq
      end

      def rename_error(name)
        "Renaming a group isn't supported. Create a SAML group link named \"#{name}\", provision the group " \
          "again from your identity provider, and then remove the old link."
      end

      def error(message)
        Gitlab::AppLogger.warn(
          message: 'Rejected a SCIM group update that changes an immutable attribute',
          scim_group_uid: scim_group_uid,
          Labkit::Fields::ERROR_MESSAGE => message
        )

        ServiceResponse.error(message: message, payload: { scim_type: SCIM_TYPE })
      end
    end
  end
end
