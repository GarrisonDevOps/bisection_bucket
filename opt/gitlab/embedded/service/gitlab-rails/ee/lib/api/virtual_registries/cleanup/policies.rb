# frozen_string_literal: true

module API
  module VirtualRegistries
    module Cleanup
      class Policies < ::API::Base
        include ::API::Concerns::VirtualRegistries::SharedAuthentication

        feature_category :virtual_registry
        urgency :low

        helpers do
          include ::Gitlab::Utils::StrongMemoize

          def group
            find_group!(params[:id])
          end
          strong_memoize_attr :group

          def policy
            ::VirtualRegistries::Cleanup::Policy.find_by_group_id!(group.id)
          end
          strong_memoize_attr :policy
        end

        after_validation do
          not_found! unless ::Feature.enabled?(:maven_virtual_registry, group)
          not_found! unless ::Gitlab.config.dependency_proxy.enabled

          unless group.licensed_feature_available?(:packages_virtual_registry) ||
              group.licensed_feature_available?(:container_virtual_registry)
            not_found!
          end

          not_found! unless ::VirtualRegistries::Setting.find_for_group(group).enabled

          authenticate!
        end

        resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          params do
            requires :id, types: [String, Integer], desc: 'The group ID or full group path. Must be a top-level group'
          end

          namespace ':id/-/virtual_registries/cleanup/policy' do
            route_setting :lifecycle, :experiment
            desc 'Get the cleanup policy for a group' do
              detail 'This feature was introduced in GitLab 18.6. \
                This feature is behind the `maven_virtual_registry` feature flag.'
              success Entities::VirtualRegistries::Cleanup::Policy
              tags %w[virtual_registries]
              hidden true
            end

            route_setting :authorization, permissions: :read_virtual_registry_cleanup_policy, boundary_type: :group
            get do
              authorize! :read_virtual_registry_cleanup_policy, group.virtual_registry_policy_subject

              present policy, with: Entities::VirtualRegistries::Cleanup::Policy
            end

            desc 'Create a new cleanup policy' do
              detail 'This feature was introduced in GitLab 18.6. \
                This feature is behind the `maven_virtual_registry` feature flag.'
              success Entities::VirtualRegistries::Cleanup::Policy
              tags %w[virtual_registries]
              hidden true
            end

            params do
              with(allow_blank: false) do
                optional :enabled, type: Boolean, desc: 'Boolean to enable/disable the policy'
                optional :keep_n_days_after_download, type: Integer, values: 1..365,
                  desc: 'Number of days after which unused cache entries should be cleaned up'
                optional :cadence, type: Integer, values: ::VirtualRegistries::Cleanup::Policy::CADENCES,
                  desc: 'How often the cleanup policy should run (daily, weekly, monthly, etc.)'
                optional :notify_on_success, type: Boolean,
                  desc: 'Boolean to notify group owners on successful cleanup runs'
                optional :notify_on_failure, type: Boolean,
                  desc: 'Boolean to notify group owners on failed cleanup runs'
              end
            end

            route_setting :lifecycle, :experiment
            route_setting :authorization, permissions: :create_virtual_registry_cleanup_policy, boundary_type: :group
            post do
              authorize! :create_virtual_registry_cleanup_policy, group.virtual_registry_policy_subject

              policy = ::VirtualRegistries::Cleanup::Policy.new(
                declared_params(include_missing: false).merge(group:)
              )

              render_validation_error!(policy) unless policy.save

              present policy, with: Entities::VirtualRegistries::Cleanup::Policy
            end

            desc 'Update the cleanup policy' do
              detail 'This feature was introduced in GitLab 18.6. \
                This feature is behind the `maven_virtual_registry` feature flag.'
              success Entities::VirtualRegistries::Cleanup::Policy
              tags %w[virtual_registries]
              hidden true
            end

            params do
              with(allow_blank: false) do
                optional :enabled, type: Boolean, desc: 'Boolean to enable/disable the policy'
                optional :keep_n_days_after_download, type: Integer, values: 1..365,
                  desc: 'Number of days after which unused cache entries should be cleaned up'
                optional :cadence, type: Integer, values: ::VirtualRegistries::Cleanup::Policy::CADENCES,
                  desc: 'How often the cleanup policy should run (daily, weekly, monthly, etc.)'
                optional :notify_on_success, type: Boolean,
                  desc: 'Boolean to notify group owners on successful cleanup runs'
                optional :notify_on_failure, type: Boolean,
                  desc: 'Boolean to notify group owners on failed cleanup runs'
              end
              at_least_one_of :enabled, :keep_n_days_after_download, :cadence, :notify_on_success, :notify_on_failure
            end

            route_setting :lifecycle, :experiment
            route_setting :authorization, permissions: :update_virtual_registry_cleanup_policy, boundary_type: :group
            patch do
              authorize! :update_virtual_registry_cleanup_policy, group.virtual_registry_policy_subject

              render_validation_error!(policy) unless policy.update(declared_params(include_missing: false))

              present policy, with: Entities::VirtualRegistries::Cleanup::Policy
            end

            desc 'Delete a cleanup policy' do
              detail 'This feature was introduced in GitLab 18.6. \
                This feature is behind the `maven_virtual_registry` feature flag.'
              success code: 204, message: 'Resource deleted'
              tags %w[virtual_registries]
              hidden true
            end

            route_setting :lifecycle, :experiment
            route_setting :authorization, permissions: :delete_virtual_registry_cleanup_policy, boundary_type: :group
            delete do
              authorize! :delete_virtual_registry_cleanup_policy, group.virtual_registry_policy_subject

              destroy_conditionally!(policy)
            end
          end
        end
      end
    end
  end
end
