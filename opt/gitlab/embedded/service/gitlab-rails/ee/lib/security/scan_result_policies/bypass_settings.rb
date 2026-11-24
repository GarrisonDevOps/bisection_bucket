# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class BypassSettings
      include Gitlab::Utils::StrongMemoize

      def initialize(bypass_settings)
        @bypass_settings = bypass_settings || {}
      end

      def access_token_ids
        bypass_settings[:access_tokens]&.pluck(:id) || []
      end
      strong_memoize_attr :access_token_ids

      def service_account_ids
        bypass_settings[:service_accounts]&.pluck(:id) || []
      end
      strong_memoize_attr :service_account_ids

      def branches
        bypass_settings[:branches] || []
      end
      strong_memoize_attr :branches

      def user_ids
        bypass_settings[:users]&.pluck(:id) || []
      end
      strong_memoize_attr :user_ids

      def group_ids
        bypass_settings[:groups]&.pluck(:id) || []
      end
      strong_memoize_attr :group_ids

      def default_roles
        Array.wrap(bypass_settings[:roles]).uniq
      end
      strong_memoize_attr :default_roles

      def custom_role_ids
        bypass_settings[:custom_roles]&.pluck(:id) || []
      end
      strong_memoize_attr :custom_role_ids

      def users_and_groups_empty?
        user_ids.empty? && group_ids.empty? && default_roles.empty? && custom_role_ids.empty?
      end

      def bypass_actors_empty?
        users_and_groups_empty? && access_token_ids.empty? && service_account_ids.empty?
      end

      private

      attr_reader :bypass_settings
    end
  end
end
