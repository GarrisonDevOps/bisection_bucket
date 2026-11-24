# frozen_string_literal: true

module EE
  module Issues
    module CreateService
      include ::Ai::DuoWorkflows::Concerns::LinkArtifact
      extend ::Gitlab::Utils::Override

      override :create
      def create(issuable, skip_system_notes: false)
        process_iteration_id
        # rubocop:disable Gitlab/ModuleWithInstanceVariables -- need to define access to this variable in
        #   process_observability_links, and stop Rails from reading `observability_links` as a model attribute.
        @observability_links = params.delete(:observability_links)
        # rubocop:enable Gitlab/ModuleWithInstanceVariables

        super
      end

      override :filter_params
      def filter_params(issue)
        filter_epic(issue)

        super
      end

      override :transaction_create
      def transaction_create(issue)
        return super unless issue.work_item_type.requirement?

        requirement = issue.build_requirement(project: issue.project)
        requirement.requirement_issue = issue

        issue.requirement_sync_error! unless requirement.valid?

        super
      end

      private

      override :assign_description_from_template
      def assign_description_from_template
        return if params[:description].present?
        return super unless container.licensed_feature_available?(:issuable_default_templates)
        return super unless container.respond_to?(:issues_template)

        super unless container.issues_template.present?
        # When a project settings template exists it takes priority over any repo Default.md.
        # Leave params[:description] unset so BuildService#issue_params_from_template applies
        # the project template directly (its else-branch) without concatenating a repo template.
      end

      override :after_create
      def after_create(issue)
        super

        link_creating_duo_workflow(issue)

        # rubocop:disable Gitlab/ModuleWithInstanceVariables -- see declaration at top of file
        ::Observability::IssueLinks::CreateService
          .new(issue.project, current_user, issue: issue, links: @observability_links)
          .execute
        # rubocop:enable Gitlab/ModuleWithInstanceVariables

        return unless issue.previous_changes.include?(:milestone_id) && issue.epic_issue

        ::Epics::UpdateDatesService.new([issue.epic_issue.epic]).execute
      end

      # Record a `created` link back to the session the request came from. Best-effort: a failure
      # never blocks issue creation.
      def link_creating_duo_workflow(issue)
        workflow = ::Ai::FlowTriggers::CallerContext.authorized_parent_workflow_for_request(current_user)

        link_artifact(workflow, link_type: :created) { ::WorkItem.find_by_id(issue.id) }
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(
          e, workflow_id: ::Gitlab::ApplicationContext.current_context_attribute(:duo_workflow_id)
        )
      end
    end
  end
end
