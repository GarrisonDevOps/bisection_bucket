# frozen_string_literal: true

module Dora
  module Watchers
    class IssueWatcher
      def self.mount(klass)
        klass.state_machine(:state_id) do
          after_transition any => :closed do |issue|
            Dora::Watchers.process_event(issue, :closed)
          end

          before_transition closed: any do |issue|
            Dora::Watchers.process_event(issue, :reopened)
          end
        end

        klass.after_create do |issue|
          Dora::Watchers.process_event(issue, :created)
        end

        klass.after_destroy do |issue|
          Dora::Watchers.process_event(issue, :deleted)
        end
      end

      attr_reader :issue, :event

      def initialize(issue, event)
        @issue = issue
        @event = event
      end

      def process
        return unless issue.work_item_type&.incident? && production_env_id

        schedule_metrics_refresh_job
      end

      private

      def schedule_metrics_refresh_job
        dates = refresh_dates
        env_id = production_env_id
        project = issue.project

        # Use run_after_commit here
        # to avoid issue object being dirty
        # when the RefreshWorker job runs.
        issue.run_after_commit do
          Gitlab::ApplicationContext.with_context(project: project, organization: project.organization) do
            dates.each do |date|
              ::Dora::DailyMetrics::RefreshWorker.perform_async(env_id, date)
            end
          end
        end
      end

      def refresh_dates
        timestamps = case event
                     when :created
                       [issue.created_at]
                     when :closed
                       [issue.closed_at]
                     when :reopened
                       [issue.closed_at_was]
                     when :deleted
                       # A deleted incident affects both the day it was opened
                       # (change failure rate) and the day it was closed
                       # (time to restore service).
                       [issue.created_at, issue.closed_at]
                     end

        timestamps.compact.map { |timestamp| timestamp.to_date.iso8601 }.uniq
      end

      def production_env_id
        @production_env_id ||= issue.project.environments.production.pick(:id)
      end
    end
  end
end
