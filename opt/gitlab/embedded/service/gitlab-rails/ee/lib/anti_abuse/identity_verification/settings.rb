# frozen_string_literal: true

module AntiAbuse
  module IdentityVerification
    class Settings
      class << self
        def arkose_client_id
          ::Gitlab::CurrentSettings.arkose_labs_client_xid
        end

        def arkose_client_secret
          ::Gitlab::CurrentSettings.arkose_labs_client_secret
        end

        def arkose_public_api_key
          ::Gitlab::CurrentSettings.arkose_labs_public_api_key || ENV['ARKOSE_LABS_PUBLIC_KEY']
        end

        def arkose_private_api_key
          ::Gitlab::CurrentSettings.arkose_labs_private_api_key || ENV['ARKOSE_LABS_PRIVATE_KEY']
        end

        def arkose_labs_domain
          "#{::Gitlab::CurrentSettings.arkose_labs_namespace}-api.arkoselabs.com"
        end

        def arkose_data_exchange_key
          ::Gitlab::CurrentSettings.arkose_labs_data_exchange_key
        end

        def arkose_enabled?(user:, user_agent:)
          return false if ::AntiAbuse::IdentityVerification::ArkoseFailOpen.active?
          return false unless ::Gitlab::CurrentSettings.arkose_labs_enabled

          arkose_public_api_key.present? &&
            arkose_private_api_key.present? &&
            ::Gitlab::CurrentSettings.arkose_labs_namespace.present? &&
            !::Gitlab::Qa.request?(user_agent) &&
            !group_saml_user(user)
        end

        private

        def group_saml_user(user)
          return unless user

          user.group_saml_identities.with_provider(::Users::BuildService::GROUP_SAML_PROVIDER).any?
        end
      end
    end
  end
end
