# frozen_string_literal: true

module SecretsManagement
  module SecretsManagers
    module UserHelper
      extend ActiveSupport::Concern

      def user_auth_mount
        'user_jwt'
      end

      def user_auth_role
        'all_users'
      end

      def user_auth_type
        'jwt'
      end

      def policy_name_for_principal(principal_type:, principal_id:)
        case principal_type
        when 'User'
          [user_path, "user_#{principal_id}"].compact.join('/')
        when 'Role'
          [role_path, principal_id].compact.join('/')
        when 'MemberRole'
          [user_path, "member_role_#{principal_id}"].compact.join('/')
        end
      end

      def user_path
        %w[users direct].compact.join('/')
      end

      def role_path
        %w[users roles].compact.join('/')
      end
    end
  end
end
