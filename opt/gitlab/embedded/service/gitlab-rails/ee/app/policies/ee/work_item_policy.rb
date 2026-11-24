# frozen_string_literal: true

module EE
  module WorkItemPolicy
    extend ActiveSupport::Concern
    prepended do
      condition(:is_epic, scope: :subject) do
        @subject.work_item_type&.epic?
      end
      condition(:related_epics_available, scope: :subject) do
        @subject.namespace.licensed_feature_available?(:related_epics)
      end

      rule { is_epic & ~related_epics_available }.prevent :admin_work_item_link

      # Special case to allow support bot assigning service desk
      # work item parents in private groups using quick actions
      rule { support_bot & service_desk_enabled }.policy do
        enable :admin_parent_link
      end

      # summarize comments is enabled at namespace(project or group) level, however if issue is confidential
      # and user(e.g. guest cannot read issue) we do not allow summarize comments
      rule { ~can?(:read_work_item) }.policy do
        prevent :summarize_comments
      end

      condition(:import_sync_read_only, scope: :subject) do
        project = @subject.project

        project && ::Import::Sync::Projects::WritePolicy.read_only?(project)
      end

      rule { import_sync_read_only }.policy do
        prevent :admin_work_item_link
        prevent :admin_parent_link
        prevent :admin_issue_relation
      end
    end
  end
end
