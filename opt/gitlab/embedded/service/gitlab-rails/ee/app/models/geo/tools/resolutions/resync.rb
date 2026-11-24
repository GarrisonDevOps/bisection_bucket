# frozen_string_literal: true

module Geo
  module Tools
    module Resolutions
      # SPIKE (gitlab-org/gitlab#602803): resets failed registries matching the error
      # pattern back to pending, delegating to the existing bulk resync service.
      # Secondary-side, reconstructable, non-destructive.
      #
      # The last_sync_failure match is a substring (ILIKE) filter, so it is not
      # index-backed. We iterate each registry table by its primary key and apply the
      # filter inside each batch rather than filtering then batching, so boundaries come
      # from the id index and the substring match only runs over BATCH_SIZE rows at a
      # time. See doc/development/database/iterating_tables_in_batches.md#slow-iteration.
      class Resync < Base
        def affected_count
          return 0 if pattern.blank?

          registry_classes.sum do |klass|
            count = 0
            klass.each_batch(of: BATCH_SIZE) { |batch| count += matching(batch).count }
            count
          end
        end

        def sample(limit: 5)
          return [] if pattern.blank?

          registry_classes.flat_map do |klass|
            matching(klass.all).limit(limit).map do |registry|
              "#{klass.name} ##{registry.id} (model #{registry.model_record_id})"
            end
          end.first(limit)
        end

        def apply(limit: nil)
          resolved = 0

          each_matching_batch(limit: limit) do |class_name, ids|
            # Reuse the blessed bulk resync service rather than duplicate its batching,
            # scoping and worker handling. Calling a service from the model layer is a
            # known wrinkle worth revisiting if this graduates from a spike.
            Geo::BulkRegistryResyncService.new(class_name, ids: ids).async_execute # rubocop:disable CodeReuse/ServiceClass -- see comment above
            resolved += ids.size
          end

          resolved
        end

        def summary(count)
          "Reset #{count} failed registries to pending for resync."
        end

        private

        def pattern
          error_type.match_pattern
        end

        def matching(relation)
          relation.with_sync_failure_matching(pattern)
        end

        def each_matching_batch(limit:)
          return if pattern.blank?

          remaining = limit

          registry_classes.each do |klass|
            klass.each_batch(of: BATCH_SIZE) do |batch|
              ids = matching(batch).pluck(klass.primary_key) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by each_batch
              ids = ids.first(remaining) if remaining

              if ids.any?
                yield klass.name, ids
                remaining -= ids.size if remaining
              end

              break if remaining && remaining <= 0
            end

            break if remaining && remaining <= 0
          end
        end
      end
    end
  end
end
