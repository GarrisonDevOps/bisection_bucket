# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PolicyStore
      class DestroyService < BaseService
        def initialize(container:, current_user:, policy_id:)
          super(container: container, current_user: current_user)

          @policy_id = policy_id
        end

        def execute
          return forbidden_error unless authorized_to_write?(:delete_govern_policy)
          return experiment_not_active_error unless experiment_active?

          policy = find_writable_policy(policy_id)
          return policy_not_found_error unless policy

          ::Gitlab::PolicyStore.delete(policy_id)

          ServiceResponse.success(payload: { policy: policy })
        rescue ::Gitlab::PolicyStore::NotFound
          policy_not_found_error
        end

        private

        attr_reader :policy_id
      end
    end
  end
end
