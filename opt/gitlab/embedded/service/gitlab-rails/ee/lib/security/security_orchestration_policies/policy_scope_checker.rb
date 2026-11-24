# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class PolicyScopeChecker
      include Gitlab::InternalEventsTracking
      include ::Gitlab::Utils::StrongMemoize

      PERSONAL_PROJECT_TYPE = 'personal'
      ARCHIVED_PROJECT_TYPE = 'archived'
      SECURITY_ATTRIBUTE_CATEGORIES = %i[business_impact application business_unit exposure].freeze

      def initialize(project:)
        @project = project
      end

      def policy_applicable?(policy, configuration: nil)
        return false if policy.blank?
        return true if policy[:policy_scope].blank?

        scope_applicable?(policy[:policy_scope], configuration: configuration)
      end

      def security_policy_applicable?(security_policy)
        return false if security_policy.blank?
        return true if security_policy.scope.blank?

        configuration = security_policy.security_orchestration_policy_configuration
        scope_applicable?(security_policy.scope.deep_symbolize_keys, configuration: configuration)
      end

      private

      attr_accessor :project

      def scope_applicable?(policy_scope, configuration: nil)
        results = collect_scope_results(policy_scope, configuration: configuration)

        # If no scopes are defined (other than match_mode), policy applies to all projects
        return true if results.empty?

        if match_mode_any?(policy_scope)
          results.any?
        else
          results.all?
        end
      end

      def collect_scope_results(policy_scope, configuration: nil)
        results = []

        # Only add results for scopes that are actually defined in the policy
        if compliance_framework_scope_defined?(policy_scope)
          results << applicable_for_compliance_framework?(policy_scope)
        end

        results << applicable_for_project?(policy_scope) if project_scope_defined?(policy_scope)

        results << applicable_for_group?(policy_scope) if group_scope_defined?(policy_scope)

        if security_attributes_scope_enabled?(configuration)
          active_categories = SECURITY_ATTRIBUTE_CATEGORIES.select do |category|
            security_category_defined?(policy_scope, category)
          end

          if active_categories.any?
            active_categories.each do |category|
              results << applicable_for_security_category?(policy_scope, category)
            end
          end
        end

        results
      end

      def match_mode_any?(policy_scope)
        policy_scope[:match_mode] == Security::PolicyScope::MATCH_MODE_ANY
      end

      def compliance_framework_scope_defined?(policy_scope)
        policy_scope[:compliance_frameworks].present?
      end

      def project_scope_defined?(policy_scope)
        policy_scope.dig(:projects, :including).present? || policy_scope.dig(:projects, :excluding).present?
      end

      def group_scope_defined?(policy_scope)
        policy_scope.dig(:groups, :including).present? || policy_scope.dig(:groups, :excluding).present?
      end

      def security_category_defined?(policy_scope, security_category)
        policy_scope.dig(security_category, :including).present? ||
          policy_scope.dig(security_category, :excluding).present?
      end

      def security_attributes_scope_enabled?(configuration)
        return false unless configuration

        configuration.experiment_enabled?(:security_attributes_policy_scope)
      end

      def applicable_for_compliance_framework?(policy_scope)
        policy_scope_compliance_frameworks = policy_scope[:compliance_frameworks].to_a

        track_policy_scope_check(:compliance_framework, [policy_scope_compliance_frameworks])

        return true if policy_scope_compliance_frameworks.blank?

        compliance_framework_ids = project.compliance_framework_ids
        return false if compliance_framework_ids.blank?

        policy_scope_compliance_frameworks.any? { |framework| framework[:id].in?(compliance_framework_ids) }
      end

      def applicable_for_project?(policy_scope)
        policy_scope_included_projects = policy_scope.dig(:projects, :including).to_a
        policy_scope_excluded_projects = policy_scope.dig(:projects, :excluding).to_a

        track_policy_scope_check(:project, [policy_scope_included_projects, policy_scope_excluded_projects])

        return false if policy_scope_excluded_projects.any? { |policy_project| policy_project[:id] == project.id }
        return false if project.personal? && policy_scope_excluded_projects.any? do |policy_project|
          policy_project[:type] == PERSONAL_PROJECT_TYPE
        end

        return false if project.archived? && policy_scope_excluded_projects.any? do |policy_project|
          policy_project[:type] == ARCHIVED_PROJECT_TYPE
        end

        return true if policy_scope_included_projects.blank?

        policy_scope_included_projects.any? { |policy_project| policy_project[:id] == project.id }
      end

      def applicable_for_security_category?(policy_scope, security_category)
        including_attrs = policy_scope.dig(security_category, :including).to_a
        excluding_attrs = policy_scope.dig(security_category, :excluding).to_a

        track_policy_scope_check(security_category, [including_attrs, excluding_attrs])

        project_attr_ids = project_security_category_attribute_ids(security_category)

        excluding_ids = excluding_attrs.pluck(:id) # rubocop:disable CodeReuse/ActiveRecord -- This is Array#pluck, not the ActiveRecord #pluck method
        return false if excluding_ids.any? { |id| id.in?(project_attr_ids) }

        return true if including_attrs.blank?

        including_ids = including_attrs.pluck(:id) # rubocop:disable CodeReuse/ActiveRecord -- This is Array#pluck, not the ActiveRecord #pluck method
        including_ids.any? { |id| id.in?(project_attr_ids) }
      end

      def all_security_attribute_ids_by_category
        project.security_attributes
          .not_deleted_with_not_deleted_categories
          .pluck_category_template_type_id
          .group_by(&:first)
          .transform_values { |pairs| pairs.map(&:last) }
      end
      strong_memoize_attr :all_security_attribute_ids_by_category

      def project_security_category_attribute_ids(security_category)
        all_security_attribute_ids_by_category.fetch(security_category.to_s, [])
      end

      def applicable_for_group?(policy_scope)
        policy_scope_included_groups = policy_scope.dig(:groups, :including).to_a
        policy_scope_excluded_groups = policy_scope.dig(:groups, :excluding).to_a

        track_policy_scope_check(:group, [policy_scope_included_groups, policy_scope_excluded_groups])

        return true if policy_scope_included_groups.blank? && policy_scope_excluded_groups.blank?

        ancestor_group_ids = project.group&.self_and_ancestor_ids.to_a

        return false if policy_scope_excluded_groups.any? { |policy_group| policy_group[:id].in?(ancestor_group_ids) }
        return true if policy_scope_included_groups.blank?

        policy_scope_included_groups.any? { |policy_group| policy_group[:id].in?(ancestor_group_ids) }
      end

      def track_policy_scope_check(policy_scope_type, collections)
        return if collections.all?(&:blank?)

        track_internal_event(
          'check_policy_scope_for_security_policy',
          project: project,
          additional_properties: {
            label: policy_scope_type.to_s # Type of the scope (project, group, compliance_framework)
          }
        )
      end
    end
  end
end
