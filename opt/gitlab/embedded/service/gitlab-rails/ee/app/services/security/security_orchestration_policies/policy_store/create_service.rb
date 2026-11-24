# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PolicyStore
      class CreateService < BaseService
        # rubocop:disable Lint/UselessMethodDefinition -- narrows params to required, unlike the base default
        def initialize(container:, current_user:, params:)
          super
        end
        # rubocop:enable Lint/UselessMethodDefinition

        def execute
          return forbidden_error unless authorized_to_write?(:create_govern_policy)
          return experiment_not_active_error unless experiment_active?
          return conflicting_scope_error if conflicting_scope?
          return default_organization_error if namespace_id.nil? && organization_shared_across_tenants?

          policy = ::Gitlab::PolicyStore.create(policy_attributes)

          ServiceResponse.success(payload: { policy: policy })
        rescue ::Gitlab::PolicyStore::EngineError => error
          engine_error(error)
        rescue ::Gitlab::PolicyStore::ValidationError => error
          ServiceResponse.error(message: error.message, reason: :invalid)
        end

        private

        def default_organization_error
          ServiceResponse.error(
            message: s_('GovernPolicies|Policies in the default organization must belong to a group'),
            reason: :unprocessable
          )
        end

        def policy_attributes
          {
            organization_id: organization.id,
            namespace_id: namespace_id,
            name: params[:name],
            description: params[:description],
            trigger_type: params[:trigger_type],
            rules: params[:rules],
            actions: params[:actions],
            policy_scope: params[:policy_scope],
            scope_rego: params[:scope_rego],
            mode: params[:mode],
            lifecycle_state: params[:lifecycle_state]
          }.compact
        end
      end
    end
  end
end
