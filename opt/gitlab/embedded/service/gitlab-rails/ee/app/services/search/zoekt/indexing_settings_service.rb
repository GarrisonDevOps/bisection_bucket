# frozen_string_literal: true

module Search
  module Zoekt
    class IndexingSettingsService
      def initialize(logger:)
        @logger = logger
      end

      def index
        logger.info(Rainbow('Starting Zoekt indexing...').green)

        settings_to_enable = {
          zoekt_indexing_enabled: true,
          zoekt_search_enabled: true,
          zoekt_auto_index_root_namespace: true,
          zoekt_indexing_paused: false
        }

        if all_settings_enabled?
          logger.info(Rainbow('Zoekt is already fully enabled (indexing, search, and auto-indexing).').orange)
        else
          unless update_settings(settings_to_enable)
            log_update_failure
            return false
          end

          logger.info(Rainbow('Zoekt indexing has been enabled.').green)
          logger.info(Rainbow('Zoekt search has been enabled.').green)
          logger.info(Rainbow('Auto-indexing of root namespaces has been enabled.').green)
          logger.info('Root namespaces will be automatically indexed by the RolloutWorker.')
          logger.info('Search will be available once indices are ready.')
          logger.info("\nTo monitor indexing progress, run: gitlab-rake gitlab:zoekt:info")
        end

        true
      end

      def disable
        logger.info(Rainbow('Disabling Zoekt...').green)

        settings_to_disable = {
          zoekt_indexing_enabled: false,
          zoekt_search_enabled: false
        }

        if ::Gitlab::CurrentSettings.zoekt_indexing_enabled? || ::Gitlab::CurrentSettings.zoekt_search_enabled?
          unless update_settings(settings_to_disable)
            log_update_failure
            return false
          end

          logger.info(Rainbow('Zoekt indexing has been disabled.').green)
          logger.info(Rainbow('Zoekt search has been disabled.').green)
        else
          logger.info(Rainbow('Zoekt is already disabled.').orange)
        end

        true
      end

      def pause_indexing
        logger.info(Rainbow('Pausing Zoekt indexing...').green)

        if ::Gitlab::CurrentSettings.zoekt_indexing_paused?
          logger.info(Rainbow('Zoekt indexing is already paused.').orange)
        else
          unless update_settings({ zoekt_indexing_paused: true })
            log_update_failure
            return false
          end

          logger.info(Rainbow('Zoekt indexing is now paused.').green)
        end

        true
      end

      def resume_indexing
        logger.info(Rainbow('Resuming Zoekt indexing...').green)

        if ::Gitlab::CurrentSettings.zoekt_indexing_paused?
          unless ::Gitlab::CurrentSettings.zoekt_indexing_enabled?
            logger.error(Rainbow('Cannot resume indexing: Zoekt indexing is disabled. Enable indexing first.').red)
            return false
          end

          unless update_settings({ zoekt_indexing_paused: false })
            log_update_failure
            return false
          end

          logger.info(Rainbow('Zoekt indexing is now unpaused.').green)
        else
          logger.info(Rainbow('Zoekt indexing is not paused.').orange)
        end

        true
      end

      def reindex_projects
        return false unless indexing_enabled?

        logger.info(Rainbow('Enqueueing projects for force reindexing...').green)
        count = 0
        Project.id_in(ENV['ID_FROM']..ENV['ID_TO']).each_batch do |batch|
          project_ids = batch.pluck_primary_key
          ::Search::Zoekt.bulk_index_async(project_ids, task_type: 'force_index_repo')
          count += project_ids.size
        end
        logger.info(Rainbow("#{count} project(s) have been enqueued for force reindexing...").green)
      end

      def reindex_failed_projects(project_ids: nil)
        return false unless indexing_enabled?

        logger.info(Rainbow('Retrying failed zoekt_repository records...').green)

        scope = ::Search::Zoekt::Repository.failed
        scope = scope.for_project_id(project_ids) if project_ids.present?

        count = 0
        scope.each_batch do |batch|
          count += batch.update_all(state: Repository.states[:pending], retries_left: 1, updated_at: Time.current)
        end
        logger.info(Rainbow("#{count} zoekt_repository record(s) have been moved to pending state.").green)
        true
      end

      private

      attr_reader :logger

      def all_settings_enabled?
        ::Gitlab::CurrentSettings.zoekt_indexing_enabled? &&
          ::Gitlab::CurrentSettings.zoekt_search_enabled? &&
          ::Gitlab::CurrentSettings.zoekt_auto_index_root_namespace? &&
          !::Gitlab::CurrentSettings.zoekt_indexing_paused?
      end

      def update_settings(settings)
        ApplicationSettings::UpdateService.new(
          Gitlab::CurrentSettings.current_application_settings,
          nil,
          settings
        ).execute
      end

      def log_update_failure
        app_setting = Gitlab::CurrentSettings.current_application_settings
        logger.error(Rainbow('Failed to update Zoekt settings.').red)

        # Trigger validation to populate errors
        app_setting.valid?

        return unless app_setting.errors.any?

        logger.error(Rainbow("Validation errors: #{app_setting.errors.full_messages.join(', ')}").red)
      end

      def indexing_enabled?
        unless ::Gitlab::CurrentSettings.zoekt_indexing_enabled?
          logger.error(Rainbow('Cannot perform indexing: Zoekt indexing is disabled. Enable indexing first.').red)
          return false
        end

        return true unless ::Gitlab::CurrentSettings.zoekt_indexing_paused?

        logger.error(Rainbow('Cannot perform indexing: Zoekt indexing is paused. Resume indexing first.').red)
        false
      end
    end
  end
end
