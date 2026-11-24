# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PolicyStore
      class UpdateService < BaseService
        def initialize(container:, current_user:, policy_id:, params:)
          super(container: container, current_user: current_user, params: params)

          @policy_id = policy_id
        end

        def execute
          return forbidden_error unless authorized_to_write?(:update_govern_policy)
          return experiment_not_active_error unless experiment_active?
          return conflicting_scope_error if conflicting_scope?
          return policy_not_found_error unless find_writable_policy(policy_id)

          policy = ::Gitlab::PolicyStore.update(policy_id, params)

          ServiceResponse.success(payload: { policy: policy })
        rescue ::Gitlab::PolicyStore::NotFound
          policy_not_found_error
        rescue ::Gitlab::PolicyStore::EngineError => error
          engine_error(error, policy_id: policy_id)
        rescue ::Gitlab::PolicyStore::ValidationError => error
          ServiceResponse.error(message: error.message, reason: :invalid)
        end

        private

        attr_reader :policy_id
      end
    end
  end
end
