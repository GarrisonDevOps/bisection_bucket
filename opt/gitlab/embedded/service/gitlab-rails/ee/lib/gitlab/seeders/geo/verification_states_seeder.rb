# frozen_string_literal: true

# rubocop:disable CodeReuse/ActiveRecord -- Seeder utility whose purpose is to create and look up records directly
module Gitlab
  module Seeders
    module Geo
      # Uses `insert_all`, not model creates: rows must carry NULL-heavy
      # shapes that model validations would reject, and replicators and
      # verification services are gated by Geo-primary checks.
      class VerificationStatesSeeder
        ROWS_PER_TABLE = 3

        VERIFICATION_COLUMNS = %w[
          verification_state
          verification_started_at
          verification_retry_at
          verification_retry_count
          verified_at
          verification_checksum
          verification_failure
        ].freeze

        def seed!
          skipped = {}

          verifiable_models.each do |parent_class|
            seed_table(parent_class, skipped)
          end

          report_skipped(skipped)
        end

        private

        def verifiable_models
          ::Gitlab::Geo::ModelMapper.available_models.select do |model|
            model.respond_to?(:separate_verification_state_table?) &&
              model.separate_verification_state_table?
          end
        end

        def seed_table(parent_class, skipped)
          state_class = parent_class.verification_state_table_class
          foreign_key = parent_class.verification_state_model_key.to_s

          parents = ensure_parents(parent_class)

          if parents.empty?
            skipped[state_class.table_name] = "no #{parent_class.name} records"
            return
          end

          insert_rows(state_class, foreign_key, state_rows(state_class, foreign_key, parents))
          print '.'
        end

        # First parents by primary key, so re-runs pick the same parents and
        # insert nothing.
        def ensure_parents(parent_class)
          parents = first_parents(parent_class)
          return parents unless parents.size < ROWS_PER_TABLE && parent_class <= ::Upload

          seed_upload_partitions
          parents = first_parents(parent_class)
          create_uploads(parent_class, ROWS_PER_TABLE - parents.size)

          first_parents(parent_class)
        end

        # UploadPartitions creates the attach-target model and one real upload
        # in every partition, so partitions whose models no fixture seeds still
        # get parents. Runs at most once, and only when a partition is short,
        # which keeps re-runs idempotent.
        def seed_upload_partitions
          return if @upload_partitions_seeded

          @upload_partitions_seeded = true
          project = ::Project.order(:id).first
          return unless project

          UploadPartitions.new(project).seed!
        end

        # Partitioned CI tables need a partition-key filter so the planner
        # prunes to one partition; an unfiltered scan trips the
        # check-ci-partition-pruning CI job.
        def first_parents(parent_class)
          scope = parent_class.order(parent_class.primary_key).limit(ROWS_PER_TABLE)
          scope = scope.where(partition_id: ::Ci::Pipeline.current_partition_value) if ci_partitioned?(parent_class)

          scope.to_a
        end

        def ci_partitioned?(klass)
          klass.table_name.start_with?('p_') && klass.column_names.include?('partition_id')
        end

        # Upload partitions are read-only; writing a regular Upload lets
        # PostgreSQL route the row to the partition by model_type.
        def create_uploads(parent_class, count)
          model = upload_model_record(parent_class)
          return unless model

          count.times do
            ::Upload.create!(
              model: model,
              uploader: 'AttachmentUploader',
              path: "geo-verification-states-seed/#{SecureRandom.hex(16)}",
              size: 1.kilobyte,
              store: ObjectStorage::Store::LOCAL
            )
          end
        end

        def upload_model_record(parent_class)
          model_type = ::Upload::PARTITION_MODEL_CLASS_NAMES.key(parent_class.name) || 'Project'

          model_type.constantize.first
        end

        def state_rows(state_class, foreign_key, parents)
          copy_columns = copy_columns_for(state_class, foreign_key)

          parents.each_with_index.map do |parent, index|
            parent.attributes.slice(*copy_columns)
              .merge(foreign_key => parent.id)
              .merge(row_shape(state_class, index))
          end
        end

        def insert_rows(state_class, foreign_key, rows)
          unique_by = state_class.column_names.include?('partition_id') ? [foreign_key, 'partition_id'] : [foreign_key]

          state_class.insert_all(rows, unique_by: unique_by)
        end

        def copy_columns_for(state_class, foreign_key)
          state_class.column_names - VERIFICATION_COLUMNS - [foreign_key, state_class.primary_key, 'id']
        end

        def row_shape(state_class, index)
          retry_count = state_class.columns_hash['verification_retry_count'].null ? nil : 0

          shape = VERIFICATION_COLUMNS.index_with(nil).merge(
            'verification_state' => verification_state_value(:verification_pending),
            'verification_retry_count' => retry_count
          )

          case index
          when 1
            shape.merge(
              'verification_state' => verification_state_value(:verification_succeeded),
              'verification_checksum' => Digest::SHA256.hexdigest('geo-verification-states-seed'),
              'verified_at' => Time.current
            )
          when 2
            shape.merge(
              'verification_state' => verification_state_value(:verification_failed),
              'verification_failure' => 'Seeded verification failure'.ljust(255, '!'),
              'verification_retry_count' => 1
            )
          else
            shape
          end
        end

        def verification_state_value(state)
          ::Geo::VerificationState::VERIFICATION_STATE_VALUES[state]
        end

        def report_skipped(skipped)
          return if skipped.empty?

          warn "\nSkipped Geo verification state tables (no parent data): " \
            "#{skipped.map { |table, reason| "#{table} (#{reason})" }.join(', ')}"
        end
      end
    end
  end
end
# rubocop:enable CodeReuse/ActiveRecord
