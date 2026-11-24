# frozen_string_literal: true

module EE
  module IssuePolicy
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    override :epics_license_available?
    def epics_license_available?
      subject_container.licensed_feature_available?(:epics) || super
    end

    override :project_work_item_epics_available?
    def project_work_item_epics_available?
      (subject_container.project_epics_enabled? && epics_license_available?) || super
    end

    prepended do
      condition(:requirement_work_item, scope: :subject) do
        @subject.work_item_type&.requirement?
      end

      condition(:project_requirements_visible_to_user) do
        project = @subject.project
        project&.licensed_feature_available?(:requirements) &&
          project.project_feature&.feature_available?(:requirements, @user)
      end

      condition(:is_epic, scope: :subject) do
        @subject.epic_work_item?
      end

      condition(:legacy_epic_unreadable) do
        !can?(:read_cross_project) && @subject.synced_epic.present?
      end

      # read_issue via GroupPolicy#read_group has no dependency on
      # :read_cross_project/external authorization, unlike :read_epic.
      rule { is_epic & external_authorization_enabled & legacy_epic_unreadable }.prevent :read_issue

      # summarize comments is enabled at namespace(project or group) level, however if issue is confidential
      # and user(e.g. guest cannot read issue) we do not allow summarize comments
      rule { ~can?(:read_issue) }.policy do
        prevent :summarize_comments
      end

      rule { ~is_incident }.policy do
        prevent :read_issuable_metric_image
        prevent :upload_issuable_metric_image
        prevent :update_issuable_metric_image
        prevent :delete_issuable_metric_image
      end

      rule { ~is_container_member }.policy do
        prevent :upload_issuable_metric_image
        prevent :update_issuable_metric_image
        prevent :delete_issuable_metric_image
      end

      # Requirements are stored as work items, but their visibility is gated by the project's requirements_access_level.
      # Without this rule, a user who can't see Requirements in the UI can still read and update requirement-typed work
      # items via the generic workItems GraphQL surface (project.workItems / workItemUpdate)
      rule { requirement_work_item & ~project_requirements_visible_to_user }.prevent_all
    end
  end
end
