# frozen_string_literal: true

module Gitlab
  module Graphql
    module Aggregations
      module SecurityOrchestrationPolicies
        class LazyComplianceFrameworkAggregate < BaseLazyAggregate
          include ConstructSecurityPolicies

          attr_reader :object, :policy_type, :current_user

          def initialize(query_ctx, object, policy_type)
            @current_user = query_ctx[:current_user]
            @object = Gitlab::Graphql::Lazy.force(object)
            @policy_type = policy_type

            super(query_ctx, object)
          end

          private

          def initial_state
            {
              pending_frameworks: [],
              loaded_objects: Hash.new { |h, k| h[k] = {} }
            }
          end

          def result
            @lazy_state[:loaded_objects][@object.id][policy_type]
          end

          def queued_objects
            @lazy_state[:pending_frameworks]
          end

          def load_queued_records
            policy_configurations_by_frameworks = @lazy_state[:pending_frameworks]
              .index_with(&:security_orchestration_policy_configurations)

            policy_configurations_by_frameworks.each do |framework, configurations|
              policies = security_policies(configurations)

              @lazy_state[:loaded_objects][framework.id] ||= {}

              policy_types_with_constructors.each do |type, constructor|
                filtered_policies = filter_policies_by_scope(policies[type], framework.id)
                unique_policies = filtered_policies.uniq do |policy|
                  [policy[:name], policy[:config].security_policy_management_project_id]
                end
                constructed = constructor.call(unique_policies)
                loaded_and_constructed = Array.wrap(@lazy_state.dig(:loaded_objects, framework.id, type)) + constructed
                @lazy_state[:loaded_objects][framework.id][type] = loaded_and_constructed
              end
            end

            @lazy_state[:pending_frameworks].clear
          end

          def policy_types_with_constructors
            {
              scan_result_policies: method(:construct_scan_result_policies),
              scan_execution_policies: method(:construct_scan_execution_policies),
              pipeline_execution_policies: method(:construct_pipeline_execution_policies),
              pipeline_execution_schedule_policies: method(:construct_pipeline_execution_schedule_policies),
              vulnerability_management_policies: method(:construct_vulnerability_management_policies)
            }
          end

          def filter_policies_by_scope(policies, framework_id)
            policies.select do |policy|
              policy.dig(:policy_scope, :compliance_frameworks)&.any? do |compliance_framework|
                compliance_framework[:id] == framework_id
              end
            end
          end

          def security_policies(configurations)
            readable_configurations = readable_configuration_per_spp(configurations)

            ::Security::SecurityPoliciesFinder.new(@current_user, readable_configurations).execute
          end

          # Configurations sharing a management project yield identical policies, which are deduplicated anyway,
          # so reading one per project avoids fanning out over every linked project or group.
          def readable_configuration_per_spp(configurations)
            configurations.group_by(&:security_policy_management_project_id).filter_map do |_, configs|
              configs.find do |config|
                Ability.allowed?(@current_user, :read_security_orchestration_policies, config.source)
              end
            end
          end

          def container
            object.namespace
          end
        end
      end
    end
  end
end
