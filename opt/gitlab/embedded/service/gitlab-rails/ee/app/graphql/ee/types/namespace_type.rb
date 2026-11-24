# frozen_string_literal: true

module EE
  module Types
    module NamespaceType
      extend ActiveSupport::Concern

      prepended do
        include ::GitlabSubscriptions::LicensedFeatureAvailability

        field :add_on_eligible_users,
          ::Types::GitlabSubscriptions::AddOnUserType.connection_type,
          null: true,
          description: 'Users in the namespace hierarchy that add-ons are applicable for. This only applies to ' \
                       'root namespaces.',
          resolver: ::Resolvers::GitlabSubscriptions::AddOnEligibleUsersResolver,
          experiment: { milestone: '16.5' }

        field :additional_purchased_storage_size,
          GraphQL::Types::Float,
          null: true,
          description: 'Additional storage purchased for the root namespace in bytes.',
          authorize: :read_namespace_via_membership

        field :total_repository_size_excess,
          GraphQL::Types::Float,
          null: true,
          description: 'Total excess repository size of all projects in the root namespace in bytes. ' \
                       'This only applies to namespaces under Project limit enforcement.',
          authorize: :read_namespace_via_membership

        field :total_repository_size,
          GraphQL::Types::Float,
          null: true,
          description: 'Total repository size of all projects in the root namespace in bytes.',
          authorize: :read_namespace_via_membership

        field :contains_locked_projects,
          GraphQL::Types::Boolean,
          null: true,
          description: 'Includes at least one project where the repository size exceeds the limit. ' \
                       'This only applies to namespaces under Project limit enforcement.',
          method: :contains_locked_projects?,
          authorize: :read_namespace_via_membership

        field :repository_size_excess_project_count,
          GraphQL::Types::Int,
          null: true,
          description: 'Number of projects in the root namespace where the repository size exceeds the limit. ' \
                       'This only applies to namespaces under Project limit enforcement.',
          authorize: :read_namespace_via_membership

        field :actual_repository_size_limit,
          GraphQL::Types::Float,
          null: true,
          description: 'Size limit for repositories in the namespace in bytes. ' \
                       'This limit only applies to namespaces under Project limit enforcement.',
          authorize: :read_namespace_via_membership

        field :actual_size_limit,
          GraphQL::Types::Float,
          null: true,
          description: 'The actual storage size limit (in bytes) based on the enforcement type ' \
                       'of either repository or namespace. This limit is agnostic of enforcement type.',
          authorize: :read_namespace_via_membership

        field :storage_size_limit,
          GraphQL::Types::Float,
          null: true,
          description: 'The storage limit (in bytes) included with the root namespace plan. ' \
                       'This limit only applies to namespaces under namespace limit enforcement.',
          authorize: :read_namespace_via_membership

        field :compliance_frameworks,
          ::Types::ComplianceManagement::ComplianceFrameworkType.connection_type,
          null: true,
          description: 'Compliance frameworks available to projects in this namespace.',
          resolver: ::Resolvers::ComplianceManagement::FrameworkResolver,
          authorize: :read_namespace_via_membership

        field :security_policies,
          ::Types::SecurityOrchestration::SecurityPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'List of security policies configured for the namespace.',
          resolver: ::Resolvers::SecurityOrchestration::SecurityPolicyResolver,
          experiment: { milestone: '18.1' }

        field :pipeline_execution_policies,
          ::Types::SecurityOrchestration::PipelineExecutionPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'Pipeline Execution Policies of the namespace.',
          resolver: ::Resolvers::SecurityOrchestration::PipelineExecutionPolicyResolver

        field :pipeline_execution_schedule_policies,
          ::Types::SecurityOrchestration::PipelineExecutionSchedulePolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'Pipeline Execution Schedule Policies of the namespace.',
          resolver: ::Resolvers::SecurityOrchestration::PipelineExecutionSchedulePolicyResolver

        field :scan_execution_policies,
          ::Types::SecurityOrchestration::ScanExecutionPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'Scan Execution Policies of the namespace.',
          resolver: ::Resolvers::SecurityOrchestration::ScanExecutionPolicyResolver

        field :scan_result_policies,
          ::Types::SecurityOrchestration::ScanResultPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          deprecated: { reason: 'Use `approvalPolicies`', milestone: '16.9' },
          description: 'Scan Result Policies of the project',
          resolver: ::Resolvers::SecurityOrchestration::ScanResultPolicyResolver

        field :approval_policies,
          ::Types::SecurityOrchestration::ApprovalPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'Approval Policies of the project',
          resolver: ::Resolvers::SecurityOrchestration::ApprovalPolicyResolver

        field :vulnerability_management_policies,
          ::Types::Security::VulnerabilityManagementPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          experiment: { milestone: '17.7' },
          description: 'Vulnerability Management Policies of the project.',
          resolver: ::Resolvers::Security::VulnerabilityManagementPolicyResolver

        field :security_policy_project,
          ::Types::ProjectType,
          null: true,
          method: :security_policy_management_project,
          description: 'Security policy project assigned to the namespace.'

        field :remote_development_cluster_agents,
          ::Types::Clusters::AgentType.connection_type,
          deprecated: { reason: 'Use `workspacesClusterAgents`', milestone: '17.8' },
          extras: [:lookahead],
          null: true,
          description: 'Cluster agents in the namespace with remote development capabilities',
          resolver: ::Resolvers::RemoteDevelopment::Namespace::ClusterAgentsResolver

        field :subscription_history,
          ::Types::GitlabSubscriptions::SubscriptionHistoryType.connection_type,
          null: true,
          description: 'Find subscription history records.',
          experiment: { milestone: '17.3' },
          method: :gitlab_subscription_histories

        field :workspaces_cluster_agents,
          ::Types::Clusters::AgentType.connection_type,
          extras: [:lookahead],
          null: true,
          description: 'Cluster agents in the namespace with workspaces capabilities',
          experiment: { milestone: '17.8' },
          resolver: ::Resolvers::RemoteDevelopment::Namespace::ClusterAgentsResolver

        field :custom_fields,
          null: true,
          description: 'Custom fields configured for the namespace.',
          resolver: ::Resolvers::Issuables::CustomFieldsResolver,
          experiment: { milestone: '17.10' },
          directives: granular_scope_directive(
            permissions: :read_custom_field,
            boundaries: [
              { boundary: :project, boundary_type: :project },
              { boundary: :itself, boundary_type: :group }
            ]
          )

        field :lifecycles, ::Types::WorkItems::LifecycleType.connection_type,
          null: true,
          description: 'Lifecycles of work items available to the namespace.',
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '18.1' },
          resolver: ::Resolvers::WorkItems::LifecyclesResolver

        field :designated_as_csp,
          GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether the namespace is designated to centrally manage security policies.',
          method: :designated_as_csp?,
          experiment: { milestone: '18.1' }

        field :statuses, ::Types::WorkItems::StatusType.connection_type,
          null: true,
          description: 'Statuses of work items available to the namespace.',
          experiment: { milestone: '18.1' },
          resolver: ::Resolvers::WorkItems::StatusesResolver,
          directives: granular_scope_directive(
            permissions: :read_work_item,
            boundaries: [
              { boundary: :project, boundary_type: :project },
              { boundary: :itself, boundary_type: :group }
            ]
          )

        field :lifecycle_templates, [::Types::WorkItems::LifecycleType],
          null: true,
          description: 'Lifecycle templates available to the namespace.',
          experiment: { milestone: '18.4' },
          authorize: :read_work_item_lifecycle

        field :plan,
          ::Types::Namespaces::PlanType,
          null: true,
          description: 'Subscription plan associated with the namespace.',
          method: :actual_plan,
          authorize: :admin_namespace,
          experiment: { milestone: '18.2' }

        field :ai_settings,
          ::Types::Ai::NamespaceSettingsType,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '18.8' },
          description: 'AI settings for the namespace.'

        field :targeted_messages,
          [::Types::Notifications::TargetedMessageType],
          null: true,
          description: 'Targeted messages for the namespace.',
          resolver: ::Resolvers::Notifications::TargetedMessageResolver,
          skip_type_authorization: :read_namespace,
          experiment: { milestone: '18.7' }

        field :licensed_feature_availability,
          ::Types::GitlabSubscriptions::LicensedFeatureAvailabilityType,
          null: false,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '18.11' },
          description: 'Check whether a licensed feature is available.' do
          argument :feature, ::Types::GitlabSubscriptions::LicensedFeatureEnum,
            required: true,
            description: 'Feature to check availability for (for example, EPICS).'
        end

        field :ai_domain_settings, GraphQL::Types::String.connection_type,
          null: true,
          description: 'List of allowed or denied domains for AI features.',
          resolver: ::Resolvers::Ai::DomainSettingsResolver,
          experiment: { milestone: '19.0' }

        field :work_item_settings,
          ::Types::WorkItems::SettingsType,
          null: true,
          resolver: ::Resolvers::WorkItems::SettingsResolver,
          experiment: { milestone: '19.0' },
          description: 'Work item settings for the namespace.'

        def additional_purchased_storage_size
          object.additional_purchased_storage_size.megabytes
        end

        def storage_size_limit
          object.root_ancestor.actual_plan.actual_limits.storage_size_limit.megabytes
        end

        def lifecycle_templates
          ::WorkItems::Statuses::SystemDefined::Templates::Lifecycle.in_namespace(object)
        end
      end
    end
  end
end
