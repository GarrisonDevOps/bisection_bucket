# frozen_string_literal: true

module Authz
  module LdapAdminRoleLinks
    class DestroyService
      def initialize(current_user, params = {})
        @current_user = current_user
        @params = params
      end

      def execute
        return error(@error) unless action_allowed?

        link = ::Authz::LdapAdminRoleLink.find(params[:id])

        if link.destroy
          ::ServiceResponse.success(payload: { ldap_admin_role_link: link })
        else
          error(link.errors.full_messages.join(', '))
        end
      rescue ActiveRecord::RecordNotFound => e
        error(e.message)
      end

      private

      attr_accessor :current_user, :params

      def action_allowed?
        @error =
          if !Ability.allowed?(current_user, :delete_ldap_admin_role_link)
            _('Unauthorized')
          elsif !::License.feature_available?(:custom_roles)
            _('custom_roles licensed feature must be available')
          end

        @error.nil?
      end

      def error(message)
        ::ServiceResponse.error(message: message)
      end
    end
  end
end
