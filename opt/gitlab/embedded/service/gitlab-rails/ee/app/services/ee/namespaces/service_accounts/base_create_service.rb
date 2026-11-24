# frozen_string_literal: true

module EE
  module Namespaces
    module ServiceAccounts
      module BaseCreateService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize

        private

        override :audit_scope
        def audit_scope(_user)
          # For namespace-level service accounts, the audit event is scoped to
          # the resource (project or group) rather than the created user.
          resource
        end

        override :creation_allowed?
        def creation_allowed?
          if saas?
            ::Authn::ServiceAccounts.creation_allowed_for_saas?(root_namespace)
          else
            super
          end
        end

        def saas?
          return false unless root_namespace

          ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        end
        strong_memoize_attr :saas?
      end
    end
  end
end
