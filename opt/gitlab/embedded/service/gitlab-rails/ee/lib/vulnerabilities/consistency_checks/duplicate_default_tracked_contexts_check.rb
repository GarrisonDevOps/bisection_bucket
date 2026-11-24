# frozen_string_literal: true

module Vulnerabilities
  module ConsistencyChecks
    class DuplicateDefaultTrackedContextsCheck < BaseCheck
      include Gitlab::ExclusiveLeaseHelpers

      LARGE_TABLES = [
        Vulnerabilities::Read,
        Vulnerabilities::Finding
      ].freeze

      SMALL_TABLES = [
        Vulnerabilities::Statistic,
        Vulnerabilities::HistoricalStatistic
      ].freeze

      def consistent?
        Feature.disabled?(:secure_consistency_check_duplicate_contexts, project)
      end

      def fix!
        in_lock("vulnerabilities:consistency_checks:duplicate_default_tracked_contexts:#{project.id}",
          ttl: 30.minutes, retries: 0) do
          duplicate_contexts = find_duplicate_default_contexts

          break if duplicate_contexts.empty?

          log('Found duplicate default tracked contexts', count: duplicate_contexts.count)

          collapse_duplicate_contexts(duplicate_contexts)
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        log('Skipping - another process is handling this project')
      end

      private

      def find_duplicate_default_contexts
        context_ids = ::Security::ProjectTrackedContext
          .where(project_id: project.id, is_default: true) # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check
          .pluck(:id) # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check

        return [] unless context_ids.size > 1

        context_ids
      end

      def collapse_duplicate_contexts(context_ids)
        survivor_id = select_survivor_context(context_ids)
        duplicate_ids = context_ids - [survivor_id]

        update_references(survivor_id, duplicate_ids)
        delete_duplicates(duplicate_ids)

        log('Collapsed duplicate contexts', survivor_id: survivor_id, deleted_ids: duplicate_ids)
      end

      def select_survivor_context(context_ids)
        contexts = ::Security::ProjectTrackedContext.where(id: context_ids).to_a # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check
        default_branch = project.default_branch

        matching = contexts.find { |c| c.context_name == default_branch }
        return matching.id if matching

        contexts.min_by(&:id).tap do |oldest|
          oldest.update!(context_name: default_branch)
        end.id
      end

      def update_references(survivor_id, duplicate_ids)
        delete_sbom_occurrences(duplicate_ids)
        update_other_tables(survivor_id, duplicate_ids)
      end

      # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check
      def delete_sbom_occurrences(duplicate_ids)
        Sbom::OccurrenceRef
          .where(project_id: project.id, security_project_tracked_context_id: duplicate_ids)
          .each_batch do |relation|
            relation.delete_all
          end
      end

      def update_other_tables(survivor_id, duplicate_ids)
        LARGE_TABLES.each do |table|
          table
            .where(project_id: project.id, security_project_tracked_context_id: duplicate_ids)
            .each_batch do |batch|
              vulnerability_ids = batch.pluck_primary_key
              batch.update_all(security_project_tracked_context_id: survivor_id)
              Vulnerabilities::EsHelper.sync_elasticsearch(vulnerability_ids) if table == Vulnerabilities::Read
            end
        end

        SMALL_TABLES.each do |table|
          table
            .where(project_id: project.id, security_project_tracked_context_id: duplicate_ids)
            .update_all(security_project_tracked_context_id: survivor_id)
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def delete_duplicates(duplicate_ids)
        ::Security::ProjectTrackedContext.where(id: duplicate_ids).delete_all # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check
      end
    end
  end
end
