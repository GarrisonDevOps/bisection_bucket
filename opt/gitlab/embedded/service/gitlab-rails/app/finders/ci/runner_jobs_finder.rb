# frozen_string_literal: true

module Ci
  class RunnerJobsFinder
    attr_reader :runner, :params

    ALLOWED_INDEXED_COLUMNS = %w[id].freeze

    def initialize(runner, current_user, params = {})
      @runner = runner
      @user = current_user
      @params = params
    end

    def execute
      return Ci::Build.none if status_dropped?

      items = if params[:system_id].blank?
                runner.builds
              else
                runner_manager = Ci::RunnerManager.for_runner(runner).with_system_xid(params[:system_id]).first
                Ci::Build.belonging_to_runner_manager(runner_manager&.id)
              end

      items = by_permission(items)
      items = by_status(items)
      sort_items(items)
    end

    private

    def by_permission(items)
      return items if @user.can_read_all_resources?

      authorized_projects = @user.authorized_project_mirrors(Gitlab::Access::REPORTER)
      # Without an authorized project the query matches nothing but reads every job, so we return no records
      return items.none if completed_statuses_limit_enabled? && !authorized_projects.exists?

      items.with_authorized_project_mirrors(authorized_projects.select(:project_id))
    end

    def by_status(items)
      return items unless Ci::HasStatus::AVAILABLE_STATUSES.include?(params[:status])

      items.with_statuses(params[:status])
    end

    # Statuses a runner's jobs can't have match nothing but make the database read every job, so we drop them
    def status_dropped?
      return false unless params[:status] && completed_statuses_limit_enabled?

      Ci::Build::RUNNER_JOB_LIST_STATUSES.exclude?(params[:status])
    end

    def completed_statuses_limit_enabled?
      Feature.enabled?(:ci_rate_limit_rest_runner_job_list_completed_statuses, @user)
    end

    # rubocop: disable CodeReuse/ActiveRecord
    def sort_items(items)
      return items unless ALLOWED_INDEXED_COLUMNS.include?(params[:order_by])

      order_by = params[:order_by]
      sort = if /\A(ASC|DESC)\z/i.match?(params[:sort])
               params[:sort]
             else
               :desc
             end

      items.order(order_by => sort)
    end
    # rubocop: enable CodeReuse/ActiveRecord
  end
end
