# frozen_string_literal: true

module EE
  module ProtectedRefs
    module AccessLevelParams
      extend ::Gitlab::Utils::Override

      override :access_levels
      def access_levels
        super + granular_access_levels
      end

      private

      override :use_default_access_level?
      def use_default_access_level?(params)
        # CE checks if deploy keys are present; if so, don't use default
        return false unless super

        # EE additionally checks for granular entries (user_id, group_id, access_level)
        entries = params[:"allowed_to_#{type}"] || []
        entries.reject { |entry| entry[:deploy_key_id].present? }.blank?
      end

      def granular_access_levels
        entries = params[:"allowed_to_#{type}"] || []
        entries.reject { |entry| entry[:deploy_key_id].present? }
      end
    end
  end
end
