# frozen_string_literal: true

module Gitlab
  module BackgroundOperation
    class EnvironmentsAutoDelete < BaseOperationWorker
      MAX_RUNTIME = 4.minutes # with one more environment's 20-second delete, a job ends within its 6-minute lease

      operation_name :delete_all
      feature_category :continuous_delivery
      cursor :id

      scope_to ->(relation) { relation.where(state: :stopped).where(auto_delete_at: ...Time.current) } # rubocop:disable CodeReuse/ActiveRecord -- Specific use-case
      reset_cursor!

      def perform
        runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)

        each_sub_batch do |sub_batch|
          deleted_count = 0
          left_ids = []

          ::Environment.id_in(sub_batch.select(:id)).preload_project_and_organization.find_each do |env|
            next left_ids << env.id if runtime_limiter.over_time?

            response = ::Environments::DestroyService.new(env.project, nil).unsafe_execute!(env)
            deleted_count += 1 if response.success?
            left_ids << env.id if response.reason == :incomplete
          end

          log_left_for_next_run(left_ids)
          deleted_count
        end
      end

      private

      def log_left_for_next_run(environment_ids)
        return if environment_ids.empty?

        Gitlab::AppLogger.info(
          Labkit::Fields::LOG_MESSAGE => 'Environments left for the next auto-delete run',
          Labkit::Fields::CLASS_NAME => self.class.name,
          environment_count: environment_ids.size,
          environment_ids: environment_ids
        )
      end
    end
  end
end
