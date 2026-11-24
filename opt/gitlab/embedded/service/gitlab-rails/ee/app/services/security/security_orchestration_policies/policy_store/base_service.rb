# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PolicyStore
      class BaseService
        def initialize(container:, current_user:, params: {})
          @container = container
          @current_user = current_user
          @params = params.to_h.symbolize_keys
        end

        private

        attr_reader :container, :current_user, :params

        def organization
          container.is_a?(::Organizations::Organization) ? container : container.organization
        end

        def namespace_id
          container.is_a?(::Group) ? container.id : nil
        end

        # nil reads every policy in the organization, and find_writable_policy grants writes on it.
        def readable_namespace_ids
          case container
          when ::Group then visible_namespace_ids_from(container.self_and_hierarchy.pluck_primary_key)
          when ::Project then visible_namespace_ids_from(container.namespace.self_and_ancestor_ids)
          else organization_shared_across_tenants? ? [] : nil
          end
        end

        def visible_namespace_ids_from(namespace_ids)
          organization_shared_across_tenants? ? namespace_ids : [nil, *namespace_ids]
        end

        def organization_shared_across_tenants?
          organization.default? && ::Gitlab::Saas.feature_available?(:policy_store_default_organization_isolation)
        end

        def experiment_active?
          container.policy_store_experiment_active?
        end

        def authorized?(ability)
          Ability.allowed?(current_user, ability, container)
        end

        def authorized_to_write?(ability)
          !container.is_a?(::Project) && authorized?(ability)
        end

        def find_readable_policy(policy_id)
          find_policy(policy_id) do |policy|
            namespace_ids = readable_namespace_ids
            namespace_ids.nil? || namespace_ids.include?(policy.namespace_id)
          end
        end

        def find_writable_policy(policy_id)
          find_policy(policy_id) do |policy|
            next policy.namespace_id == namespace_id if namespace_id

            readable_namespace_ids.nil?
          end
        end

        # A policy outside the container returns the same not-found as a missing id,
        # so probing ids leaks nothing.
        def find_policy(policy_id)
          policy = ::Gitlab::PolicyStore.find(policy_id)

          return unless policy.organization_id == organization.id
          return unless yield(policy)

          policy
        rescue ::Gitlab::PolicyStore::NotFound
          nil
        end

        def experiment_not_active_error
          ServiceResponse.error(
            message: experiment_not_active_message,
            reason: :experiment_not_active
          )
        end

        def experiment_not_active_message
          if container.is_a?(::Group)
            s_('GovernPolicies|Policy Store experiment is not active for this group')
          else
            s_('GovernPolicies|Policy Store experiment is not active for this organization')
          end
        end

        def forbidden_error
          ServiceResponse.error(
            message: forbidden_message,
            reason: :forbidden
          )
        end

        def forbidden_message
          case container
          when ::Group
            s_('GovernPolicies|You are not authorized to perform this action on policies in this group')
          when ::Project
            s_('GovernPolicies|You are not authorized to perform this action on policies in this project')
          else
            s_('GovernPolicies|You are not authorized to perform this action on policies in this organization')
          end
        end

        def policy_not_found_error
          ServiceResponse.error(
            message: s_('GovernPolicies|Policy was not found'),
            reason: :not_found
          )
        end

        def engine_error(error, **context)
          ::Gitlab::ErrorTracking.track_exception(error, organization_id: organization.id, **context)

          ServiceResponse.error(message: error.message, reason: :engine_error)
        end

        def conflicting_scope?
          params[:policy_scope].present? && params[:scope_rego].present?
        end

        def conflicting_scope_error
          ServiceResponse.error(
            message: s_('GovernPolicies|Only one of policy_scope or scope_rego can be provided'),
            reason: :invalid
          )
        end
      end
    end
  end
end
