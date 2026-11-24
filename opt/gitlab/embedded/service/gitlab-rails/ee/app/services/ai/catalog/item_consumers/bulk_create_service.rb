# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      class BulkCreateService
        include Gitlab::Utils::StrongMemoize
        include ::Ai::Catalog::Loggable

        SKIPPED_REASONS = %i[already_configured already_inherited].freeze

        def initialize(
          current_user:, item:, projects:, trigger_types: nil, trigger_filter: nil,
          trigger_goals: nil, pinned_version: nil)
          @current_user = current_user
          @item = item
          @projects = projects
          @trigger_types = trigger_types
          @trigger_filter = trigger_filter
          @trigger_goals = trigger_goals
          @pinned_version = pinned_version
        end

        def execute
          failures = []
          warnings = []

          projects.each do |project|
            response = ::Ai::Catalog::ItemConsumers::CreateService.new(
              container: project,
              current_user: current_user,
              params: create_service_params
            ).execute

            if !response.success? && SKIPPED_REASONS.exclude?(response.reason)
              failures << { project_id: project.id, error_message: Array(response.message).join(', ') }
            end

            Array(response.payload[:warnings]).each do |warning|
              warnings << { project_id: project.id, message: warning }
            end
          rescue StandardError => e
            Gitlab::ErrorTracking.track_exception(e, project_id: project.id, item_id: item.id)
            failures << {
              project_id: project.id,
              error_message: s_('AICatalog|Something went wrong on our end whilst processing this project')
            }
          end

          log_failures(failures)
          log_warnings(warnings)

          ServiceResponse.success(
            payload: {
              successful_count: projects.size - failures.count,
              failures: failures,
              warnings: warnings
            }
          )
        end

        private

        attr_reader :current_user, :item, :projects, :trigger_types, :trigger_filter, :trigger_goals,
          :pinned_version

        def log_warnings(warnings)
          ai_catalog_logger.context(item:)

          warnings.each do |warning|
            ai_catalog_logger.warn(
              message: 'Partially created item consumer for project',
              project_id: warning[:project_id],
              warning_message: warning[:message]
            )
          end
        end

        def log_failures(failures)
          ai_catalog_logger.context(item:)

          failures.each do |failure|
            ai_catalog_logger.error(
              message: 'Failed to create item consumer for project',
              project_id: failure[:project_id],
              error_message: failure[:error_message]
            )
          end
        end

        # Memoized: params are passed to CreateService once per project in a loop, and
        # CreateService mutates the hash it receives. Safe only because
        # BaseContainerService dups params on init, so each call gets its own copy.
        strong_memoize_attr def create_service_params
          {
            item: item,
            trigger_types: trigger_types,
            trigger_filter: trigger_filter,
            trigger_goals: trigger_goals,
            pinned_version: pinned_version,
            kind: :direct
          }.compact
        end
      end
    end
  end
end
