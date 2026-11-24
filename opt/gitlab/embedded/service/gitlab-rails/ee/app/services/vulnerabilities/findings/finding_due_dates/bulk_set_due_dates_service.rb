# frozen_string_literal: true

module Vulnerabilities
  module Findings
    module FindingDueDates
      class BulkSetDueDatesService
        include Gitlab::Allowable
        include Gitlab::Utils::StrongMemoize
        include ::Gitlab::InternalEventsTracking

        BATCH_SIZE = 1000

        SKIPPED_SENTINEL = Object.new.freeze

        ERRORS = {
          invalid_due_date: "Invalid due_date: %{value}. Expected Date, ISO8601 string, or nil.",
          not_found: "Finding not found."
        }.freeze

        # @param updates [Array<Hash>] list of update instructions
        #
        # Each update must have the shape:
        #   {
        #     finding_uuid: String,      # UUID of the finding
        #     due_date: Date | String | nil
        #   }
        #
        # - `due_date` can be:
        #   - Date: used as-is
        #   - ISO8601 String: parsed into Date
        #   - nil: removes existing due date
        #
        # Notes:
        # - Inputs are assumed to be valid; no structural validation is performed.
        # - Invalid `due_date` values (failed parsing) are skipped with an error.
        # - Duplicate UUIDs are allowed - Last-Write-Wins (LWW).
        def initialize(project:, current_user:, updates:)
          @project = project
          @current_user = current_user
          @updates = updates
        end

        def execute
          authorize!

          errors = []
          normalized = normalized_updates(errors)

          totals = change_batches!(normalized[:due_dates_by_uuid], errors).each_with_object(
            { assigned: 0, removed: 0, skipped: normalized[:skipped_count] }
          ) do |(type, value), acc|
            next acc[:skipped] += value if type.equal?(SKIPPED_SENTINEL)

            acc[:assigned] += upsert_batch(value[:upserts])
            acc[:removed] += delete_batch(value[:deletes])
          ensure
            # Each write commits on its own, so sync what committed even if a later write fails.
            sync_changed_vulnerabilities
          end

          if updates.present?
            track_internal_event(
              'bulk_set_vulnerability_due_dates',
              user: current_user,
              project: project,
              additional_properties: {
                updates_count: updates.size,
                assigned_count: totals[:assigned],
                removed_count: totals[:removed],
                skipped_count: totals[:skipped],
                error_count: errors.size
              }
            )
          end

          ServiceResponse.success(payload: totals.merge(errors: errors))
        end

        private

        attr_reader :project, :current_user, :updates

        def authorize!
          raise Gitlab::Access::AccessDeniedError unless
            project.is_a?(::Project) &&
              current_user.is_a?(::User) &&
              can?(current_user, :admin_vulnerability, project)
        end

        def normalized_updates(errors)
          return empty_updates_result if updates.blank?

          updates.each_with_object(empty_updates_result) do |update, acc|
            normalized = normalize_due_date(update[:due_date])

            if !update[:due_date].nil? && normalized.nil?
              acc[:skipped_count] += 1
              next append_error(errors, update[:finding_uuid], :invalid_due_date, value: update[:due_date].inspect)
            end

            acc[:due_dates_by_uuid][update[:finding_uuid]] = normalized
          end
        end

        def empty_updates_result
          { due_dates_by_uuid: {}, skipped_count: 0 }
        end

        def normalize_due_date(due_date)
          return due_date if due_date.is_a?(Date) || due_date.nil?

          Date.iso8601(due_date)
        rescue ArgumentError, TypeError
        end

        def change_batches!(due_dates_by_uuid, errors)
          return to_enum(__method__, due_dates_by_uuid, errors) unless block_given?

          due_dates_by_uuid.keys.each_slice(BATCH_SIZE) do |uuid_batch|
            findings = findings_by_uuids(uuid_batch)

            missing = uuid_batch - findings.map(&:uuid)
            missing.each { |uuid| append_error(errors, uuid, :not_found) }
            yield(SKIPPED_SENTINEL, missing.size) if missing.any?

            result = findings.each_with_object(upserts: [], deletes: []) do |finding, result|
              if finding.project_id != project.id
                append_error(errors, finding.uuid, :not_found) && yield(SKIPPED_SENTINEL, 1)
                next
              end

              vulnerability_ids_by_finding_id[finding.id] = finding.vulnerability_id
              due_date = due_dates_by_uuid[finding.uuid]

              next result[:deletes] << finding.id if due_date.nil?

              result[:upserts] << build_upsert_row(finding.id, finding.project_id, due_date)
            end

            next if result[:upserts].empty? && result[:deletes].empty?

            yield(nil, result)
          end
        end

        def findings_by_uuids(uuids)
          Vulnerabilities::Finding.by_uuid(uuids).select(:id, :uuid, :project_id, :vulnerability_id)
        end

        def upsert_batch(batch)
          return 0 if batch.empty?

          table = Vulnerabilities::FindingDueDate.arel_table

          on_duplicate = Arel.sql(
            "#{table[:due_date].name} = EXCLUDED.#{table[:due_date].name}, " \
              "#{table[:updated_at].name} = EXCLUDED.#{table[:updated_at].name} " \
              "WHERE #{table.name}.#{table[:due_date].name} IS DISTINCT FROM EXCLUDED.#{table[:due_date].name}"
          )

          # Unchanged rows are skipped by the WHERE above, so only changed findings are returned.
          upserted = Vulnerabilities::FindingDueDate.upsert_all(
            batch,
            unique_by: :vulnerability_occurrence_id,
            on_duplicate: on_duplicate,
            returning: :vulnerability_occurrence_id
          )
          changed_finding_ids.concat(upserted.rows.flatten)

          batch.size
        end

        def delete_batch(batch)
          return 0 if batch.empty?

          existing = Vulnerabilities::FindingDueDate.by_finding_ids(batch)
          finding_ids = existing.pluck_finding_ids
          existing.delete_all.tap { changed_finding_ids.concat(finding_ids) }
        end

        def sync_changed_vulnerabilities
          ::Vulnerabilities::EsHelper.sync_elasticsearch(vulnerability_ids_by_finding_id.values_at(*changed_finding_ids))
          changed_finding_ids.clear
        end

        def build_upsert_row(finding_id, project_id, due_date)
          {
            vulnerability_occurrence_id: finding_id,
            project_id: project_id,
            due_date: due_date,
            created_at: now,
            updated_at: now
          }
        end

        def append_error(errors, uuid, key, **vars)
          errors << {
            uuid: uuid,
            code: key,
            message: format(ERRORS[key], **vars)
          }
        end

        def now
          Time.current
        end
        strong_memoize_attr :now

        def changed_finding_ids
          @changed_finding_ids ||= []
        end

        def vulnerability_ids_by_finding_id
          @vulnerability_ids_by_finding_id ||= {}
        end
      end
    end
  end
end
