# frozen_string_literal: true

module EE
  module PersonalAccessTokensHelper
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    def personal_access_token_expiration_policy_enabled?
      instance_level_personal_access_token_expiration_policy_enabled?
    end

    def personal_access_token_max_expiry_date
      instance_level_personal_access_token_max_expiry_date
    end

    def personal_access_token_max_expiry_days
      ::Gitlab::CurrentSettings.max_personal_access_token_lifetime
    end

    def personal_access_token_expiration_policy_licensed?
      ::License.feature_available?(:personal_access_token_expiration_policy)
    end

    def max_personal_access_token_lifetime_in_days
      ::PersonalAccessToken.max_expiration_lifetime_in_days
    end

    private

    def instance_level_personal_access_token_expiration_policy_enabled?
      instance_level_personal_access_token_max_expiry_date && personal_access_token_expiration_policy_licensed?
    end

    def instance_level_personal_access_token_max_expiry_date
      ::Gitlab::CurrentSettings.max_personal_access_token_lifetime_from_now
    end
  end
end
