# frozen_string_literal: true

module Vulnerabilities
  class BaseBulkUpdateService
    include Gitlab::Allowable

    MAX_BATCH = 100

    def initialize(current_user, vulnerability_ids, comment)
      @user = current_user
      @vulnerability_ids = vulnerability_ids
      @comment = comment
      @project_ids = []
    end

    def execute
      ensure_authorized_projects!

      vulnerability_ids.each_slice(MAX_BATCH).each do |ids|
        update(ids)
      end

      refresh_statistics

      ServiceResponse.success(payload: {
        vulnerabilities: Vulnerability.id_in(vulnerability_ids)
      })
    rescue ActiveRecord::ActiveRecordError
      ServiceResponse.error(message: "Could not modify vulnerabilities")
    end

    attr_reader :vulnerability_ids, :user, :comment, :project_ids

    protected

    def update(vulnerabilities_ids)
      raise NotImplementedError
    end

    def ensure_authorized_projects!
      raise Gitlab::Access::AccessDeniedError unless authorized_and_ff_enabled_for_all_projects?
    end

    def authorized_and_ff_enabled_for_all_projects?
      @project_ids = Vulnerability.id_in(vulnerability_ids).distinct.select(:project_id).map(&:project_id) # rubocop: disable CodeReuse/ActiveRecord -- context specific

      Project.id_in(project_ids)
             .with_group
             .with_namespace
             .include_project_feature
             .all? do |project|
        authorized_for_project(project)
      end
    end

    def authorized_for_project(project)
      can?(user, required_permission, project)
    end

    def required_permission
      :admin_vulnerability
    end

    def refresh_statistics
      return if project_ids.empty?

      Vulnerabilities::Statistics::AdjustmentWorker.perform_async(project_ids)
    end

    # We use this for setting the created_at and updated_at timestamps
    # for the various records created by this service.
    # The time is memoized on the first call to this method so all of the
    # created records will have the same timestamps.
    def now
      @now ||= Time.current.utc
    end
  end
end
