# frozen_string_literal: true

module EE
  module Issues # rubocop:disable Gitlab/BoundedContexts -- FOSS finder is not bounded to a context
    module IssueTypesFilter
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      private

      override :by_issue_types
      def by_issue_types(issues)
        return super unless authorize_issue_types?
        return issues.model.none unless valid_param_types?

        return without_epic_type(issues) unless epic_type_allowed?
        return without_epic_type_in_projects(issues) unless epic_type_allowed_in_group_projects?

        filter_by_param_types(issues)
      end

      override :filter_by_authorized_type_ids
      def filter_by_authorized_type_ids(issues, ids)
        return super unless ids.present? && ids.include?(epic_type_id)
        return super if epic_type_allowed?

        filtered_ids = ids.reject { |id| id == epic_type_id }
        return issues.model.none if filtered_ids.empty?

        super(issues, filtered_ids)
      end

      def epic_type_id
        ::WorkItems::TypesFramework::Provider.new(parent).find_by_base_type(:epic)&.id
      end
      strong_memoize_attr :epic_type_id

      def authorize_issue_types?
        return false if param_types.any? && param_types.exclude?('epic')

        ::Feature.enabled?(:authorize_issue_types_in_finder, parent&.root_ancestor, type: :gitlab_com_derisk)
      end

      def epic_type_allowed?
        return false unless parent&.licensed_feature_available?(:epics)
        return false if parent.is_a?(Project) && !parent.project_epics_enabled?

        true
      end

      def epic_type_allowed_in_group_projects?
        return true unless parent.is_a?(Group)

        parent.project_epics_enabled?
      end

      def without_epic_type_in_projects(issues)
        project_epics = issues.with_issue_type('epic').project_level

        filtered_issues = filter_by_param_types(issues)
        filtered_issues.id_not_in(project_epics)
      end

      def without_epic_type(issues)
        return issues.without_issue_type('epic') if param_types.blank?

        allowed_param_types = param_types.excluding('epic')
        allowed_param_types.any? ? issues.with_issue_type(allowed_param_types) : issues.model.none
      end

      def filter_by_param_types(issues)
        param_types.any? ? issues.with_issue_type(param_types) : issues
      end
    end
  end # rubocop:enable Gitlab/BoundedContexts
end
