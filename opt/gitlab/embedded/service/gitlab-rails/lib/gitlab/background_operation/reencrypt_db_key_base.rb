# frozen_string_literal: true

module Gitlab
  module BackgroundOperation
    # Re-encrypts with the current `db_key_base` key the rows of a table that an older key encrypted.
    # There's one operation per table of {Gitlab::Encryption::DbKeyBaseRotation::Registry}. `rotation_id`
    # is {.current_rotation_id}, which gives each rotation its own operations.
    #
    # A new operation of a rotation starts after the highest cursor of the last one, even when it failed,
    # so the rows it missed are left to the verification pass, which starts from the table's beginning.
    #
    # The cursor is set per class, so this class batches the tables keyed on `id`, and its subclasses
    # the tables keyed on another column.
    class ReencryptDbKeyBase < BaseOperationWorker
      JOB_CLASS_NAMES = {
        'id' => 'ReencryptDbKeyBase',
        'project_id' => 'ReencryptDbKeyBaseByProjectId',
        'user_id' => 'ReencryptDbKeyBaseByUserId'
      }.freeze

      # The re-encrypted rows are the affected rows of `operation_name`
      OTHER_OUTCOMES = %i[skipped conflict error].freeze

      operation_name :update_all
      feature_category :cell
      cursor :id
      job_arguments :rotation_id

      RotationMismatchError = Class.new(StandardError)

      ROTATION_ID_LABEL = 'gitlab:db_key_base_rotation:v1'
      # OWASP's PBKDF2-HMAC-SHA256 figure: the ID is logged, and an operator may set a weak key
      ROTATION_ID_ITERATIONS = 600_000

      # Derived from every configured key, in order, so removing a retired key starts a new rotation.
      # `Key#id` has only 16 bits and names the current key alone.
      #
      # @return [String]
      def self.current_rotation_id
        secrets = Gitlab::Encryption::KeyProvider[:db_key_base].decryption_keys.map do |key|
          [key.secret.bytesize].pack('N') + key.secret.b
        end

        OpenSSL::KDF.pbkdf2_hmac(secrets.join, salt: ROTATION_ID_LABEL, iterations: ROTATION_ID_ITERATIONS,
          length: 8, hash: 'sha256').unpack1('H*')
      end

      # @param table [Gitlab::Encryption::DbKeyBaseRotation::Table]
      # @return [String] the name of the class whose cursor is the table's primary key, to enqueue
      def self.job_class_name(table)
        JOB_CLASS_NAMES.fetch(table.key_columns.first)
      end

      def perform
        check_rotation!

        reencryptor = Gitlab::Encryption::DbKeyBaseRotation::TableReencryptor.new(table)
        counts = Gitlab::Encryption::DbKeyBaseRotation::TableReencryptor::Counts.zero

        each_sub_batch do |sub_batch|
          sub_batch_counts = reencryptor.reencrypt(cursor_range(sub_batch, table.key_columns))
          counts += sub_batch_counts
          record_other_outcomes(sub_batch_counts)

          sub_batch_counts.reencrypted
        end

        log_counts(counts)
      end

      private

      # A node with other keys, such as a stale config, would skip or miss rows. The framework retries a
      # failed job at most 3 times, after the last batch, so every node must have the keys before enqueuing.
      def check_rotation!
        current_id = self.class.current_rotation_id
        return if current_id == rotation_id

        raise RotationMismatchError, "the current db_key_base rotation is #{current_id}, not #{rotation_id}"
      end

      def table
        @table ||= Gitlab::Encryption::DbKeyBaseRotation::Registry.tables
          .find { |table| table.name == batch_table.to_s }
          .tap { |table| check_table!(table) }
      end

      # Reads use the operation's connection, writes the model's. On another database, the read would find
      # the locked, empty copy of the table. With another cursor, {#cursor_range} could be reversed. Either
      # way, the job would succeed without re-encrypting anything.
      def check_table!(table)
        raise ArgumentError, "#{batch_table} has no column encrypted with db_key_base" unless table

        schema = Gitlab::Database::GitlabSchema.table_schema!(batch_table.to_s)
        unless Gitlab::Database.gitlab_schemas_for_connection(connection).include?(schema)
          raise ArgumentError, "#{batch_table} is in #{schema}, which the " \
            "#{Gitlab::Database.db_config_name(connection)} database does not serve"
        end

        return if self.class.cursor_columns.map(&:to_s) == [table.key_columns.first]

        raise ArgumentError, "#{batch_table} is keyed on #{table.key_columns.first}, not on " \
          "#{self.class.cursor_columns.join(', ')}; enqueue #{self.class.job_class_name(table)}"
      end

      # A sub-batch is the next rows in cursor order, with a `LIMIT`. {Table#filter} must narrow their
      # cursor range instead, or the `LIMIT` would pick matching rows beyond the sub-batch. The rest of
      # the primary key holds the partition key of a partitioned table, so the read is pruned.
      # rubocop:disable CodeReuse/ActiveRecord -- generic over every table with encrypted columns
      def cursor_range(sub_batch, key_columns)
        return sub_batch if key_columns.one? && !table.model.respond_to?(:db_key_base_reencryption_filter)

        rows = sub_batch.pluck(*key_columns).map { |row| Array.wrap(row) }
        return sub_batch.none if rows.empty?

        cursor_values, *other_values = rows.transpose
        conditions = { key_columns.first => cursor_values.first..cursor_values.last }
        key_columns.drop(1).zip(other_values) { |column, values| conditions[column] = values.uniq }

        sub_batch.unscope(:order, :limit).where(conditions)
      end
      # rubocop:enable CodeReuse/ActiveRecord

      # Kept in the job metrics next to the affected rows, where the status task reads them
      def record_other_outcomes(counts)
        OTHER_OUTCOMES.each do |outcome|
          (batch_metrics.affected_rows[outcome] ||= []) << counts[outcome]
        end
      end

      # The job metrics already hold the counts, so only jobs with rows left behind are logged
      def log_counts(counts)
        return if counts.conflict == 0 && counts.error == 0

        Gitlab::AppLogger.info(
          Labkit::Fields::CLASS_NAME => self.class.name,
          Labkit::Fields::LOG_MESSAGE => 'db_key_base_reencryption_rows_left',
          table_name: batch_table.to_s,
          rotation_id: rotation_id,
          reencrypted_count: counts.reencrypted,
          skipped_count: counts.skipped,
          conflict_count: counts.conflict,
          error_count: counts.error
        )
      end
    end
  end
end
