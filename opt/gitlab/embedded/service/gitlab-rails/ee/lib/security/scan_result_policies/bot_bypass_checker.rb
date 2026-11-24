# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class BotBypassChecker
      include Gitlab::Utils::StrongMemoize

      def initialize(bypass_settings:, user:)
        @bypass_settings = bypass_settings
        @user = user
      end

      def bypass_allowed?
        return false unless user

        service_account_id.present? || access_token_ids.present?
      end

      def service_account_id
        return unless user.service_account?
        return unless bypass_settings.service_account_ids.include?(user.id)

        user.id
      end
      strong_memoize_attr :service_account_id

      def access_token_ids
        return unless user.project_bot?
        return if bypass_settings.access_token_ids.blank?

        user.personal_access_tokens.active.id_in(bypass_settings.access_token_ids).pluck_primary_key.presence
      end
      strong_memoize_attr :access_token_ids

      private

      attr_reader :bypass_settings, :user
    end
  end
end
