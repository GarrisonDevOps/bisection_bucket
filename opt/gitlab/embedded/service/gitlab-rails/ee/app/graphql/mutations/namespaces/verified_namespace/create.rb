# frozen_string_literal: true

module Mutations
  module Namespaces
    module VerifiedNamespace
      class Create < Mutations::BaseMutation
        graphql_name 'VerifiedNamespaceCreate'

        description 'Create a verified namespace and mark all child catalog resources ' \
          'with the passed verification level info.'

        include ::GitlabSubscriptions::SubscriptionHelper

        authorize :admin_all_resources
        authorize_granular_token permissions: :create_verified_namespace, boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        include Mutations::ResolvesNamespace

        argument :namespace_path,
          GraphQL::Types::ID,
          required: true,
          description: 'Root namespace path.'

        argument :verification_level,
          Types::Namespaces::VerificationLevelEnum,
          required: true,
          description: 'Verification level for a root namespace.'

        def resolve(namespace_path:, verification_level:)
          if self_managed_or_dedicated? && !verification_level.in?(%w[verified_creator_self_managed unverified])
            { errors: ["Cannot use #{verification_level} on a non-Gitlab.com instance." \
              "Use `VERIFIED_CREATOR_SELF_MANAGED` or `UNVERIFIED`."] }
          elsif allowed_verification?(verification_level)
            namespace = authorized_find!(namespace_path: namespace_path)
            result = ::Namespaces::VerifyNamespaceService.new(namespace, verification_level).execute

            errors = result.success? ? [] : [result.message]
            {
              errors: errors
            }
          end
        end

        private

        def self_managed_or_dedicated?
          !gitlab_com_subscription?
        end

        def allowed_verification?(verification_level)
          (self_managed_or_dedicated? && verification_level.in?(%w[verified_creator_self_managed unverified])) ||
            gitlab_com_subscription?
        end

        def find_object(namespace_path:)
          resolve_namespace(full_path: namespace_path)
        end
      end
    end
  end
end
