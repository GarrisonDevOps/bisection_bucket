# frozen_string_literal: true

module Authz
  module LdapAdminRoleLinks
    class CreateService
      def initialize(current_user, params = {})
        @current_user = current_user
        @params = params
      end

      def execute
        return licensed_feature_error unless ::License.feature_available?(:custom_roles)
        return authorized_error unless allowed?
        return member_role_error unless params[:member_role].admin_related_role?

        admin_link = ::Authz::LdapAdminRoleLink.new(params)

        if admin_link.save
          ::ServiceResponse.success(payload: { ldap_admin_role_link: admin_link })
        else
          ::ServiceResponse.error(message: admin_link.errors.full_messages.join(', '))
        end
      end

      private

      attr_accessor :current_user, :params

      def allowed?
        Ability.allowed?(current_user, :create_ldap_admin_role_link)
      end

      def authorized_error
        ::ServiceResponse.error(message: _('Unauthorized'), reason: :unauthorized)
      end

      def member_role_error
        ::ServiceResponse.error(message: _('Only admin custom roles can be assigned'), reason: :bad_request)
      end

      def licensed_feature_error
        ::ServiceResponse.error(message: _('custom_roles licensed feature must be available'))
      end
    end
  end
end
