# frozen_string_literal: true

module Gitlab
  module Graphql
    module Aggregations
      module SecurityOrchestrationPolicies
        class LazyDastProfileAggregate < BaseLazyAggregate
          attr_reader :dast_profile, :current_user

          def initialize(query_ctx, dast_profile)
            if !dast_profile.is_a?(DastSiteProfile) && !dast_profile.is_a?(DastScannerProfile)
              raise ArgumentError, 'only DastSiteProfile or DastScannerProfile are allowed'
            end

            @dast_profile = Gitlab::Graphql::Lazy.force(dast_profile)
            @current_user = query_ctx[:current_user]

            super
          end

          private

          def initial_state
            {
              dast_pending_profiles: [],
              loaded_objects: {}
            }
          end

          def result
            @lazy_state[:loaded_objects][dast_profile]
          end

          def queued_objects
            @lazy_state[:dast_pending_profiles]
          end

          def load_queued_records
            # The record hasn't been loaded yet, so
            # hit the database with all pending IDs to prevent N+1
            profiles_by_project_id = @lazy_state[:dast_pending_profiles].group_by(&:project_id)
            projects = ::ProjectsFinder.new(current_user: @current_user, project_ids_relation: profiles_by_project_id.keys).execute
            policy_configurations = projects.each_with_object({}) do |project, configurations|
              configurations[project.id] = project.all_security_orchestration_policy_configurations
            end

            profiles_by_project_id.each do |project_id, dast_pending_profiles|
              dast_pending_profiles.each do |profile|
                @lazy_state[:loaded_objects][profile] = active_policy_names_for_profile(policy_configurations[project_id], profile)
              end
            end

            @lazy_state[:dast_pending_profiles].clear
          end

          def active_policy_names_for_profile(policy_configurations, profile)
            return [] if policy_configurations.blank?

            policy_configurations.flat_map do |policy_configuration|
              case profile
              when DastSiteProfile
                policy_configuration.active_policy_names_with_dast_site_profile(profile.name)
              when DastScannerProfile
                policy_configuration.active_policy_names_with_dast_scanner_profile(profile.name)
              end.to_a
            end
          end
        end
      end
    end
  end
end
