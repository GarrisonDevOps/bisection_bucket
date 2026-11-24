# frozen_string_literal: true

module EE
  module Gitlab
    module PersonalAccessTokens
      class ServiceAccountTokenValidator
        include ::Gitlab::Utils::StrongMemoize

        def initialize(service_account_user)
          @service_account_user = service_account_user
        end

        attr_accessor :service_account_user

        def expiry_enforced?
          unless service_account_user.service_account?
            return ::Gitlab::CurrentSettings.require_personal_access_token_expiry?
          end

          return true if free_tier?

          if saas?
            return true unless service_account_scoped_to_group?

            return service_account_user.provisioned_by_group
              .namespace_settings.service_access_tokens_expiration_enforced
          end

          ::Gitlab::CurrentSettings.current_application_settings.service_access_tokens_expiration_enforced
        end

        def saas?
          ::Gitlab::Saas.enabled?
        end
        strong_memoize_attr :saas?

        def service_account_scoped_to_group?
          service_account_user.provisioned_by_group.present?
        end

        def free_tier?
          if saas?
            group = service_account_user.provisioned_by_group
            return false unless group

            ::Authn::ServiceAccounts.free_tier_namespace?(group)
          else
            ::Authn::ServiceAccounts.free_tier?
          end
        end
      end
    end
  end
end
