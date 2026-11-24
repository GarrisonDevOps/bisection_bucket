# frozen_string_literal: true

module EE
  module Issues
    module BuildService
      extend ::Gitlab::Utils::Override
      include ::Observability::ObservabilityIssuesHelper

      override :set_work_item_type
      def set_work_item_type(issue)
        raw_param = params[:work_item_type_id].presence || params[:work_item_type]
        type = work_item_type_provider.fetch_work_item_type(raw_param)

        return super unless type.try(:non_converted_custom_type?)

        extract_work_item_type_param # Remove work item type from params

        # Validate container type - custom types can only be created in projects for now
        unless container.is_a?(Project) || container.is_a?(Namespaces::ProjectNamespace)
          issue.errors.add(:work_item_type, 'custom types can only be created in projects')
          return super
        end

        # Validate license - only check in the create flow, existing items should continue to work
        unless container.licensed_feature_available?(:configurable_work_item_types)
          issue.errors.add(:base, 'Configurable work item types are not available')
          return super
        end

        issue.work_item_type = type
      end

      def issue_params_from_template
        return {} unless container.feature_available?(:issuable_default_templates)
        return {} unless container.respond_to?(:issues_template)

        if container.issues_template.present? && params.include?(:description)
          { description: container.issues_template + "\n" + params.delete(:description).to_s }
        else
          { description: container.issues_template }
        end
      end

      # Issue params can be built from 3 types of passed params,
      # They take precedence over eachother like this
      # passed params > discussion params > template params
      # The template params are filled in here, and might be overwritten by super
      override :build_issue_params
      def build_issue_params
        issue_params_from_template
          .merge(super)
          .merge(observability_issue_params)
          .with_indifferent_access
      end

      private

      # A work item the session's service account creates is stored under the human who started the
      # session. Sessions with no human have the service account as their user, so it stays the author.
      override :author
      def author
        actor = super
        return actor unless ::Feature.enabled?(:agent_presence_consolidation, container.root_ancestor)

        session_human || actor
      end

      def session_human
        workflow = ::Ai::FlowTriggers::CallerContext.authorized_parent_workflow_for_request(current_user)
        return unless workflow&.session_service_account?(current_user)

        workflow.user if workflow.user.human? && workflow.user == current_user
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(
          e, workflow_id: ::Gitlab::ApplicationContext.current_context_attribute(:duo_workflow_id)
        )
        nil
      end
    end
  end
end
