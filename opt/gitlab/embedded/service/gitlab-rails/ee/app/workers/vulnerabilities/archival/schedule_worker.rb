# frozen_string_literal: true

module Vulnerabilities
  module Archival
    class ScheduleWorker
      include ApplicationWorker
      include CronjobQueue
      include Gitlab::Utils::StrongMemoize

      REDIS_CURSOR_KEY = 'vulnerability_archival/last_scheduling_information'

      feature_category :vulnerability_management
      data_consistency :sticky
      idempotent!

      BATCH_SIZE = 500
      DELAY_INTERVAL = 30.seconds.to_i

      def perform
        archive_before = 1.year.ago.to_date.to_s
        index = latest_index.to_i

        scope.each_batch(of: BATCH_SIZE) do |relation|
          projects = Project.id_in(relation).with_namespace
          namespaces = projects.map(&:namespace)
          last_project = projects.last

          ::Namespaces::Preloaders::NamespaceRootAncestorPreloader.new(namespaces).execute

          projects = projects.select { |project| ::Vulnerabilities::Archival.enabled_for?(project) }

          next store_state(index, last_project) unless projects.present?

          Vulnerabilities::Archival::ArchiveWorker.bulk_perform_in_with_contexts(
            index * DELAY_INTERVAL,
            projects,
            arguments_proc: ->(project) { [project.id, archive_before] },
            context_proc: ->(project) { { project: project } })

          store_state(index + 1, last_project)

          index += 1
        end
      end

      private

      def scope
        project_settings_with_vulnerabilities = ProjectSetting.has_vulnerabilities

        return project_settings_with_vulnerabilities unless last_iterated_project_id

        project_settings_with_vulnerabilities.where('project_id > ?', last_iterated_project_id) # rubocop:disable CodeReuse/ActiveRecord -- Very specific use case.
      end

      def latest_index
        last_iteration_information['index'] || 1
      end

      def last_iterated_project_id
        last_iteration_information['project_id']
      end

      def store_state(index, project)
        redis_cursor.commit(index: index, project_id: project.id)
      end

      def last_iteration_information
        @last_iteration_information ||= redis_cursor.cursor
      end

      def redis_cursor
        @redis_cursor ||= Gitlab::Redis::CursorStore.new(REDIS_CURSOR_KEY)
      end
    end
  end
end
