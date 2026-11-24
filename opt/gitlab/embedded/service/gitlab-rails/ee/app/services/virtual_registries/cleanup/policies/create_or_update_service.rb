# frozen_string_literal: true

module VirtualRegistries
  module Cleanup
    module Policies
      class CreateOrUpdateService
        ALLOWED_ATTRIBUTES = %i[
          enabled
          keep_n_days_after_download
          cadence
          notify_on_success
          notify_on_failure
        ].freeze

        ERRORS = {
          unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
          invalid_params: ServiceResponse.error(message: 'Invalid parameters provided', reason: :invalid_params)
        }.freeze

        def initialize(group:, current_user:, params:)
          @group = group
          @current_user = current_user
          @params = params
        end

        def execute
          return ERRORS[:unauthorized] unless allowed?
          return ERRORS[:invalid_params] unless valid_params_key?
          return ERRORS[:invalid_params] unless policy.new_record? || params.present?

          policy.update!(policy_params)

          ServiceResponse.success(payload: { virtual_registries_cleanup_policy: policy })
        rescue ActiveRecord::ActiveRecordError => e
          ServiceResponse.error(message: e.message, reason: :persistence_error)
        end

        private

        attr_reader :group, :current_user, :params

        def allowed?
          Ability.allowed?(current_user, :update_virtual_registry_cleanup_policy, group.virtual_registry_policy_subject)
        end

        def policy
          @policy ||= ::VirtualRegistries::Cleanup::Policy.find_for_group(group)
        end

        def valid_params_key?
          params.blank? || (params.keys & ALLOWED_ATTRIBUTES).any?
        end

        def policy_params
          params&.slice(*ALLOWED_ATTRIBUTES) || {}
        end
      end
    end
  end
end
