# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class PolicyScopeFetcher
      include ::GitlabSubscriptions::SubscriptionHelper

      def initialize(policy_scope:, container:, current_user:)
        @policy_scope = policy_scope
        @container = container
        @current_user = current_user
      end

      def execute
        return empty_result if policy_scope.blank?

        including_projects, excluding_projects = scoped_projects
        including_groups, excluding_groups = scoped_groups

        result = {
          match_mode: match_mode,
          compliance_frameworks: compliance_frameworks,
          excluding_personal_projects: excluding_personal_projects?,
          excluding_archived_projects: excluding_archived_projects?,
          including_projects: including_projects,
          excluding_projects: excluding_projects,
          including_groups: including_groups,
          excluding_groups: excluding_groups
        }

        Security::PolicyScope::SECURITY_ATTRIBUTE_SCOPE_KEYS.each_key do |scope_key|
          including_attrs, excluding_attrs = scoped_security_attributes_for(scope_key)
          result[:"including_#{scope_key}_attributes"] = including_attrs
          result[:"excluding_#{scope_key}_attributes"] = excluding_attrs
        end

        result
      end

      private

      attr_reader :policy_scope, :container, :current_user

      def empty_result
        {
          match_mode: match_mode,
          compliance_frameworks: [],
          excluding_personal_projects: false,
          excluding_archived_projects: false,
          including_projects: [],
          excluding_projects: [],
          including_groups: [],
          excluding_groups: [],
          including_business_impact_attributes: [],
          excluding_business_impact_attributes: [],
          including_application_attributes: [],
          excluding_application_attributes: [],
          including_business_unit_attributes: [],
          excluding_business_unit_attributes: [],
          including_exposure_attributes: [],
          excluding_exposure_attributes: []
        }
      end

      def match_mode
        policy_scope&.dig(:match_mode) || Security::PolicyScope::DEFAULT_MATCH_MODE
      end

      def compliance_frameworks
        compliance_framework_ids = policy_scope[:compliance_frameworks]&.pluck(:id)

        return [] if compliance_framework_ids.blank?

        if !gitlab_com_subscription? && root_ancestor.nil?
          ComplianceManagement::Framework.id_in(compliance_framework_ids)
        elsif root_ancestor.present?
          root_ancestor.compliance_management_frameworks.id_in(compliance_framework_ids)
        else
          []
        end
      end

      def scoped_projects
        scoped_resources(:projects, projects_scope)
      end

      def scoped_groups
        scoped_resources(:groups, groups_scope)
      end

      # Mirrors #compliance_frameworks: instance-wide only for a self-managed instance-level
      # policy (no container); otherwise scoped to the policy's own root ancestor so a policy
      # can never resolve a project/group from outside its own hierarchy.
      def projects_scope
        if !gitlab_com_subscription? && root_ancestor.nil?
          Project
        elsif root_ancestor.present?
          root_ancestor.all_projects
        else
          Project.none
        end
      end

      def groups_scope
        if !gitlab_com_subscription? && root_ancestor.nil?
          Group
        elsif root_ancestor.present?
          root_ancestor.self_and_descendants
        else
          Group.none
        end
      end

      def scoped_security_attributes_for(scope_key)
        template_type = Security::PolicyScope::SECURITY_ATTRIBUTE_SCOPE_KEYS[scope_key]
        scoped_security_attributes(scope_key, template_type)
      end

      def scoped_security_attributes(category_key, template_type)
        return [[], []] unless container

        included_ids = policy_scope.dig(category_key, :including)&.pluck(:id) || []
        excluded_ids = policy_scope.dig(category_key, :excluding)&.pluck(:id) || []
        ids = included_ids + excluded_ids

        return [[], []] if ids.empty?

        attributes = security_attributes(ids, template_type)

        [attributes.values_at(*included_ids).compact, attributes.values_at(*excluded_ids).compact]
      end

      def security_attributes(ids, template_type)
        ::Security::Attribute
          .by_namespace(root_ancestor)
          .by_category_template_type(template_type)
          .id_in(ids)
          .index_by(&:id)
      end

      def scoped_resources(resource_type, root_ancestor_resources)
        included_ids = policy_scope.dig(resource_type, :including)&.pluck(:id) || []
        excluded_ids = policy_scope.dig(resource_type, :excluding)&.pluck(:id) || []
        ids = included_ids + excluded_ids

        return [[], []] if ids.empty?

        resources = root_ancestor_resources.id_in(ids).index_by(&:id)
        including_resources = resources.values_at(*included_ids).compact
        excluding_resources = resources.values_at(*excluded_ids).compact

        [including_resources, excluding_resources]
      end

      def root_ancestor
        return if container.nil?

        if container.is_a?(ComplianceManagement::Framework)
          container.namespace
        else
          container.root_ancestor
        end
      end

      def excluding_personal_projects?
        excluding_projects_by_type?(PolicyScopeChecker::PERSONAL_PROJECT_TYPE)
      end

      def excluding_archived_projects?
        excluding_projects_by_type?(PolicyScopeChecker::ARCHIVED_PROJECT_TYPE)
      end

      def excluding_projects_by_type?(type)
        return false if policy_scope.blank?

        excluding_projects = policy_scope.dig(:projects, :excluding)
        return false if excluding_projects.blank?

        excluding_projects.any? { |project| project[:type] == type }
      end
    end
  end
end
