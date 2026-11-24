# frozen_string_literal: true

module API
  module Govern
    class Policies < ::API::Base
      include ::API::PaginationParams
      include ::API::APIGuard

      allow_access_with_scope ::Gitlab::Auth::StatelessAccessTokenGate::POLICY_STORE_SCOPE,
        if: ->(request) do
          (request.get? || request.head?) &&
            request.path.match?(%r{/organizations/\d+/security/policy_store\z})
        end

      UnmappedReasonError = Class.new(StandardError)

      UNMAPPED_REASON_MESSAGE = 'Could not complete the policy store request'

      TEXT_LIMITS = ::Gitlab::PolicyStore::Ports::PolicyRepository::TEXT_LIMITS

      feature_category :security_policy_management
      urgency :low

      helpers do
        def present_policies(policies)
          present policies, with: ::API::Entities::Govern::Policy,
            disclosed_namespace_ids: disclosed_namespace_ids_for(Array.wrap(policies))
        end

        def disclosed_namespace_ids_for(policies)
          namespace_ids = policies.filter_map(&:namespace_id).uniq
          return [] if namespace_ids.empty?

          groups = ::Group.id_in(namespace_ids).to_a
          ::Preloaders::GroupPolicyPreloader.new(groups, current_user).execute

          groups.select { |group| can?(current_user, :read_group, group) }.map(&:id)
        end

        def render_policy_store_error!(response)
          case response.reason
          when :not_found
            not_found!('Policy')
          when :experiment_not_active
            not_found!
          when :forbidden
            forbidden!(response.message)
          when :invalid
            render_api_error!(response.message, :bad_request)
          when :unprocessable
            render_api_error!(response.message, :unprocessable_entity)
          when :engine_error
            render_api_error!(response.message, :internal_server_error)
          else
            ::Gitlab::ErrorTracking.track_exception(
              UnmappedReasonError.new("Unmapped policy store reason: #{response.reason}"),
              service_message: response.message
            )

            render_api_error!(UNMAPPED_REASON_MESSAGE, :internal_server_error)
          end
        end
      end

      before do
        not_found! unless ::Gitlab::CurrentSettings.policy_store_experiment_enabled?
        forbidden! unless ::License.feature_available?(:security_orchestration_policies)
      end

      resource :security do
        before do
          actor = safe_find_organization_actor_from_sources
          not_found! unless actor.is_a?(::User) && api_access_allowed?(actor)

          # safe_find_organization_actor_from_sources only resolves identity: it does not
          # validate the token or enforce granular scopes the way current_user does, so both
          # are done explicitly here, with any failure folded into the same 404 as a bad actor.
          authorize_granular_token_scopes!(validate_and_save_access_token!(scopes: scopes_registered_for_endpoint))

          not_found! unless ::Feature.enabled?(:security_policies_v2, actor.organization)
        rescue ::Gitlab::Auth::AuthenticationError
          not_found!
        end

        desc 'List the triggers a security policy can target' do
          detail 'Lists the triggers available when creating a policy in the policy store.'
          success ::API::Entities::Govern::Trigger
          is_array true
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[policy_store]
          hidden true
        end
        route_setting :authorization, todo: 'https://gitlab.com/gitlab-org/gitlab/-/work_items/598030'
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        get 'policy_store/triggers' do
          present ::Gitlab::PolicyStore::Triggers::ALL, with: ::API::Entities::Govern::Trigger
        end

        desc 'List the actions a security policy can take' do
          detail 'Lists the actions available when creating a policy in the policy store.'
          success ::API::Entities::Govern::Action
          is_array true
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[policy_store]
          hidden true
        end
        route_setting :authorization, todo: 'https://gitlab.com/gitlab-org/gitlab/-/work_items/598030'
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        get 'policy_store/actions' do
          present ::Gitlab::PolicyStore::Actions::ALL, with: ::API::Entities::Govern::Action
        end

        desc 'List the rule kinds a security policy can be built from' do
          detail 'Lists the rule kinds available when creating a policy in the policy store.'
          success ::API::Entities::Govern::Rule
          is_array true
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[policy_store]
          hidden true
        end
        route_setting :authorization, todo: 'https://gitlab.com/gitlab-org/gitlab/-/work_items/598030'
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        get 'policy_store/rules' do
          present ::Gitlab::PolicyStore::Rules::ALL, with: ::API::Entities::Govern::Rule
        end
      end

      resource :organizations do
        helpers do
          include ::Gitlab::Utils::StrongMemoize

          def organization
            find_organization!(params[:id])
          end
          strong_memoize_attr :organization

          def authorized_organization!(ability)
            authorize! ability, organization

            organization
          end
        end

        before do
          authenticate!
        end

        # after_validation, not before, so a non-numeric :id fails Grape's own
        # type: Integer validation with 400 instead of reaching find_organization!.
        after_validation do
          not_found! unless ::Feature.enabled?(:security_policies_v2, organization)
        end

        desc 'List the security policies of an organization' do
          detail 'Lists the policies stored in the policy store for the given organization.'
          success ::API::Entities::Govern::Policy
          is_array true
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: Integer, desc: 'The ID of the organization'
          optional :trigger_type, type: String,
            values: ::Gitlab::PolicyStore::Triggers::ALL.map { |trigger| trigger[:id] },
            desc: 'Return only the policies that respond to this trigger'
          optional :namespace_ids, type: Array[Integer],
            desc: 'Return only the policies of these namespaces, usually a group and its ancestors, plus the ' \
              'organization-wide policies, except in the default organization on GitLab.com'
          optional :lifecycle_state, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::LIFECYCLE_STATES +
              [::Security::SecurityOrchestrationPolicies::PolicyStore::ListService::ALL_LIFECYCLE_STATES],
            default: ::Gitlab::PolicyStore::Ports::PolicyRepository::DEFAULT_LIFECYCLE_STATE,
            desc: 'Return only active policies (default), only disabled policies, or every policy regardless ' \
              'of lifecycle state'
          use :pagination
        end
        route_setting :authorization, permissions: :read_govern_policy, boundary_type: :instance
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        get ':id/security/policy_store' do
          verify_pagination_params!

          organization = authorized_organization!(:read_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::ListService
            .new(
              container: organization, current_user: current_user, trigger_type: params[:trigger_type],
              namespace_ids: params[:namespace_ids], lifecycle_state: params[:lifecycle_state],
              page: params[:page], per_page: params[:per_page]
            )
            .execute

          render_policy_store_error!(response) if response.error?

          payload = response.payload
          next_page = payload[:page] + 1 if payload[:has_next_page]
          prev_page = payload[:page] - 1 if payload[:page] > 1

          ::Gitlab::Pagination::OffsetHeaderBuilder.new(
            request_context: self, per_page: payload[:per_page], page: payload[:page],
            next_page: next_page, prev_page: prev_page
          ).execute(data_without_counts: true)

          present_policies(payload[:policies])
        end

        desc 'Get a security policy of an organization' do
          detail 'Gets a single policy from the policy store for the given organization.'
          success ::API::Entities::Govern::Policy
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: Integer, desc: 'The ID of the organization'
          requires :policy_id, type: Integer, desc: 'The ID of the policy'
        end
        route_setting :authorization, permissions: :read_govern_policy, boundary_type: :instance
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        get ':id/security/policy_store/:policy_id' do
          organization = authorized_organization!(:read_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::FindService
            .new(container: organization, current_user: current_user, policy_id: params[:policy_id])
            .execute

          render_policy_store_error!(response) if response.error?

          present_policies(response.payload[:policy])
        end

        desc 'Create a security policy in an organization' do
          detail 'Creates a policy in the policy store for the given organization.'
          success code: 201, model: ::API::Entities::Govern::Policy
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 422, message: 'Unprocessable entity' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: Integer, desc: 'The ID of the organization'
          requires :name, type: String, limit: TEXT_LIMITS[:name], desc: 'Name of the policy'
          optional :description, type: String, limit: TEXT_LIMITS[:description],
            desc: 'Description of the policy'
          requires :trigger_type, type: String,
            values: ::Gitlab::PolicyStore::Triggers::ALL.map { |trigger| trigger[:id] },
            desc: 'Trigger the policy responds to'
          requires :rules, type: Array, allow_blank: false, no_blank_elements: true,
            desc: 'Rules of the policy, at least one' do
            requires :type, type: String,
              values: ::Gitlab::PolicyStore::Rules::ALL.map { |rule| rule[:id] },
              desc: 'Type of the rule'
            # Two types because a custom rule's value is Rego source, while a calendar or
            # environment rule's is a configuration hash.
            optional :value, types: [String, Hash], desc: 'Value the rule evaluates, shaped by its type'
          end
          optional :actions, type: Array, no_blank_elements: true, desc: 'Actions the policy takes' do
            requires :type, type: String,
              values: ::Gitlab::PolicyStore::Actions::ALL.map { |action| action[:id] },
              desc: 'Type of the action'
            optional :value, type: Hash, desc: 'Configuration the action uses'
          end
          optional :mode, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::MODES,
            desc: 'Enforcement mode of the policy'
          optional :lifecycle_state, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::LIFECYCLE_STATES,
            desc: 'Lifecycle state of the policy'
          optional :policy_scope, type: Hash, desc: 'Authored scope of the policy'
          optional :scope_rego, type: String, limit: TEXT_LIMITS[:scope_rego],
            desc: 'Scope of the policy, authored as Rego'
        end
        route_setting :authorization, permissions: :create_govern_policy, boundary_type: :instance
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        post ':id/security/policy_store' do
          organization = authorized_organization!(:create_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::CreateService
            .new(
              container: organization,
              current_user: current_user,
              params: declared_params(include_missing: false).except(:id)
            )
            .execute

          render_policy_store_error!(response) if response.error?

          present_policies(response.payload[:policy])
        end

        desc 'Update a security policy of an organization' do
          detail 'Changes a policy in the policy store for the given organization.'
          success ::API::Entities::Govern::Policy
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: Integer, desc: 'The ID of the organization'
          requires :policy_id, type: Integer, desc: 'The ID of the policy'
          optional :name, type: String, limit: TEXT_LIMITS[:name], desc: 'Name of the policy'
          optional :description, type: String, limit: TEXT_LIMITS[:description],
            desc: 'Description of the policy'
          optional :trigger_type, type: String,
            values: ::Gitlab::PolicyStore::Triggers::ALL.map { |trigger| trigger[:id] },
            desc: 'Trigger the policy responds to'
          optional :rules, type: Array, no_blank_elements: true, desc: 'Rules of the policy' do
            requires :type, type: String,
              values: ::Gitlab::PolicyStore::Rules::ALL.map { |rule| rule[:id] },
              desc: 'Type of the rule'
            optional :value, types: [String, Hash], desc: 'Value the rule evaluates, shaped by its type'
          end
          optional :actions, type: Array, no_blank_elements: true, desc: 'Actions the policy takes' do
            requires :type, type: String,
              values: ::Gitlab::PolicyStore::Actions::ALL.map { |action| action[:id] },
              desc: 'Type of the action'
            optional :value, type: Hash, desc: 'Configuration the action uses'
          end
          optional :mode, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::MODES,
            desc: 'Enforcement mode of the policy'
          optional :lifecycle_state, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::LIFECYCLE_STATES,
            desc: 'Lifecycle state of the policy'
          optional :policy_scope, type: Hash, desc: 'Authored scope of the policy'
          optional :scope_rego, type: String, limit: TEXT_LIMITS[:scope_rego],
            desc: 'Scope of the policy, authored as Rego'
          at_least_one_of :name, :description, :trigger_type, :rules, :actions, :mode, :lifecycle_state,
            :policy_scope, :scope_rego
        end
        route_setting :authorization, permissions: :update_govern_policy, boundary_type: :instance
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        patch ':id/security/policy_store/:policy_id' do
          organization = authorized_organization!(:update_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::UpdateService
            .new(
              container: organization,
              current_user: current_user,
              policy_id: params[:policy_id],
              params: declared_params(include_missing: false).except(:id, :policy_id)
            )
            .execute

          render_policy_store_error!(response) if response.error?

          present_policies(response.payload[:policy])
        end

        desc 'Delete a security policy of an organization' do
          detail 'Deletes a policy from the policy store for the given organization.'
          success code: 204
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: Integer, desc: 'The ID of the organization'
          requires :policy_id, type: Integer, desc: 'The ID of the policy'
        end
        route_setting :authorization, permissions: :delete_govern_policy, boundary_type: :instance
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        delete ':id/security/policy_store/:policy_id' do
          organization = authorized_organization!(:delete_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::DestroyService
            .new(container: organization, current_user: current_user, policy_id: params[:policy_id])
            .execute

          render_policy_store_error!(response) if response.error?

          no_content!
        end
      end

      resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        helpers do
          include ::Gitlab::Utils::StrongMemoize

          def group
            find_group!(params[:id])
          end
          strong_memoize_attr :group

          def authorized_group!(ability)
            authorize! ability, group

            group
          end
        end

        before do
          authenticate!
        end

        after_validation do
          not_found! unless ::Feature.enabled?(:security_policies_v2, group.organization)
        end

        desc 'List the security policies of a group' do
          detail 'Lists the policies stored in the policy store for the given group.'
          success ::API::Entities::Govern::Policy
          is_array true
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: String, desc: 'The ID or URL-encoded path of the group'
          optional :trigger_type, type: String,
            values: ::Gitlab::PolicyStore::Triggers::ALL.map { |trigger| trigger[:id] },
            desc: 'Return only the policies that respond to this trigger'
          optional :lifecycle_state, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::LIFECYCLE_STATES +
              [::Security::SecurityOrchestrationPolicies::PolicyStore::ListService::ALL_LIFECYCLE_STATES],
            default: ::Gitlab::PolicyStore::Ports::PolicyRepository::DEFAULT_LIFECYCLE_STATE,
            desc: 'Return only active policies (default), only disabled policies, or every policy regardless ' \
              'of lifecycle state'
          use :pagination
        end
        route_setting :authorization, permissions: :read_govern_policy, boundary_type: :group
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        get ':id/security/policy_store' do
          verify_pagination_params!
          group = authorized_group!(:read_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::ListService
            .new(
              container: group, current_user: current_user, trigger_type: params[:trigger_type],
              lifecycle_state: params[:lifecycle_state], page: params[:page], per_page: params[:per_page]
            )
            .execute

          render_policy_store_error!(response) if response.error?

          payload = response.payload
          next_page = payload[:page] + 1 if payload[:has_next_page]
          prev_page = payload[:page] - 1 if payload[:page] > 1

          ::Gitlab::Pagination::OffsetHeaderBuilder.new(
            request_context: self, per_page: payload[:per_page], page: payload[:page],
            next_page: next_page, prev_page: prev_page
          ).execute(data_without_counts: true)

          present_policies(payload[:policies])
        end

        desc 'Get a security policy of a group' do
          detail 'Gets a single policy from the policy store for the given group.'
          success ::API::Entities::Govern::Policy
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: String, desc: 'The ID or URL-encoded path of the group'
          requires :policy_id, type: Integer, desc: 'The ID of the policy'
        end
        route_setting :authorization, permissions: :read_govern_policy, boundary_type: :group
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        get ':id/security/policy_store/:policy_id' do
          group = authorized_group!(:read_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::FindService
            .new(container: group, current_user: current_user, policy_id: params[:policy_id])
            .execute

          render_policy_store_error!(response) if response.error?

          present_policies(response.payload[:policy])
        end

        desc 'Create a security policy in a group' do
          detail 'Creates a policy in the policy store for the given group.'
          success code: 201, model: ::API::Entities::Govern::Policy
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: String, desc: 'The ID or URL-encoded path of the group'
          requires :name, type: String, limit: TEXT_LIMITS[:name], desc: 'Name of the policy'
          optional :description, type: String, limit: TEXT_LIMITS[:description],
            desc: 'Description of the policy'
          requires :trigger_type, type: String,
            values: ::Gitlab::PolicyStore::Triggers::ALL.map { |trigger| trigger[:id] },
            desc: 'Trigger the policy responds to'
          requires :rules, type: Array, allow_blank: false, no_blank_elements: true,
            desc: 'Rules of the policy, at least one' do
            requires :type, type: String,
              values: ::Gitlab::PolicyStore::Rules::ALL.map { |rule| rule[:id] },
              desc: 'Type of the rule'
            optional :value, types: [String, Hash], desc: 'Value the rule evaluates, shaped by its type'
          end
          optional :actions, type: Array, no_blank_elements: true, desc: 'Actions the policy takes' do
            requires :type, type: String,
              values: ::Gitlab::PolicyStore::Actions::ALL.map { |action| action[:id] },
              desc: 'Type of the action'
            optional :value, type: Hash, desc: 'Configuration the action uses'
          end
          optional :mode, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::MODES,
            desc: 'Enforcement mode of the policy'
          optional :lifecycle_state, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::LIFECYCLE_STATES,
            desc: 'Lifecycle state of the policy'
          optional :policy_scope, type: Hash, desc: 'Authored scope of the policy'
          optional :scope_rego, type: String, limit: TEXT_LIMITS[:scope_rego],
            desc: 'Scope of the policy, authored as Rego'
        end
        route_setting :authorization, permissions: :create_govern_policy, boundary_type: :group
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        post ':id/security/policy_store' do
          group = authorized_group!(:create_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::CreateService
            .new(
              container: group,
              current_user: current_user,
              params: declared_params(include_missing: false).except(:id)
            )
            .execute

          render_policy_store_error!(response) if response.error?

          present_policies(response.payload[:policy])
        end

        desc 'Update a security policy of a group' do
          detail 'Changes a policy in the policy store for the given group.'
          success ::API::Entities::Govern::Policy
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: String, desc: 'The ID or URL-encoded path of the group'
          requires :policy_id, type: Integer, desc: 'The ID of the policy'
          optional :name, type: String, limit: TEXT_LIMITS[:name], desc: 'Name of the policy'
          optional :description, type: String, limit: TEXT_LIMITS[:description],
            desc: 'Description of the policy'
          optional :trigger_type, type: String,
            values: ::Gitlab::PolicyStore::Triggers::ALL.map { |trigger| trigger[:id] },
            desc: 'Trigger the policy responds to'
          optional :rules, type: Array, no_blank_elements: true, desc: 'Rules of the policy' do
            requires :type, type: String,
              values: ::Gitlab::PolicyStore::Rules::ALL.map { |rule| rule[:id] },
              desc: 'Type of the rule'
            optional :value, types: [String, Hash], desc: 'Value the rule evaluates, shaped by its type'
          end
          optional :actions, type: Array, no_blank_elements: true, desc: 'Actions the policy takes' do
            requires :type, type: String,
              values: ::Gitlab::PolicyStore::Actions::ALL.map { |action| action[:id] },
              desc: 'Type of the action'
            optional :value, type: Hash, desc: 'Configuration the action uses'
          end
          optional :mode, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::MODES,
            desc: 'Enforcement mode of the policy'
          optional :lifecycle_state, type: String,
            values: ::Gitlab::PolicyStore::Ports::PolicyRepository::LIFECYCLE_STATES,
            desc: 'Lifecycle state of the policy'
          optional :policy_scope, type: Hash, desc: 'Authored scope of the policy'
          optional :scope_rego, type: String, limit: TEXT_LIMITS[:scope_rego],
            desc: 'Scope of the policy, authored as Rego'
          at_least_one_of :name, :description, :trigger_type, :rules, :actions, :mode, :lifecycle_state,
            :policy_scope, :scope_rego
        end
        route_setting :authorization, permissions: :update_govern_policy, boundary_type: :group
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        patch ':id/security/policy_store/:policy_id' do
          group = authorized_group!(:update_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::UpdateService
            .new(
              container: group,
              current_user: current_user,
              policy_id: params[:policy_id],
              params: declared_params(include_missing: false).except(:id, :policy_id)
            )
            .execute

          render_policy_store_error!(response) if response.error?

          present_policies(response.payload[:policy])
        end

        desc 'Delete a security policy of a group' do
          detail 'Deletes a policy from the policy store for the given group.'
          success code: 204
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 500, message: 'Internal server error' }
          ]
          tags %w[policy_store]
          hidden true
        end
        params do
          requires :id, type: String, desc: 'The ID or URL-encoded path of the group'
          requires :policy_id, type: Integer, desc: 'The ID of the policy'
        end
        route_setting :authorization, permissions: :delete_govern_policy, boundary_type: :group
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        delete ':id/security/policy_store/:policy_id' do
          group = authorized_group!(:delete_govern_policy)

          response = ::Security::SecurityOrchestrationPolicies::PolicyStore::DestroyService
            .new(container: group, current_user: current_user, policy_id: params[:policy_id])
            .execute

          render_policy_store_error!(response) if response.error?

          no_content!
        end
      end
    end
  end
end
