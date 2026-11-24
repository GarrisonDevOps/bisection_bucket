# frozen_string_literal: true

module Gitlab
  module Encryption
    module DbKeyBaseRotation
      # Re-encrypts a table's rows that an older `db_key_base` key encrypted. Each row is written with
      # a compare-and-swap `update_all`, so a concurrent edit is never overwritten.
      class TableReencryptor
        # Reported in place of a column's error
        ColumnError = Class.new(StandardError)

        # Rows by outcome. They add up to the rows read.
        Counts = Struct.new(:reencrypted, :skipped, :conflict, :error) do
          def self.zero
            new(0, 0, 0, 0)
          end

          def +(other)
            self.class.new(*to_a.zip(other.to_a).map(&:sum))
          end
        end

        # @param table [Table] the table to re-encrypt
        # @param dry_run [Boolean] count the rows to re-encrypt without writing them
        def initialize(table, dry_run: false)
          @table = table
          @dry_run = dry_run
          @reported_failures = Set.new
        end

        # Re-encrypts the rows of `relation` that {Table#filter} keeps. They are read with `pluck`, so
        # no model is instantiated and no `after_initialize` callback runs.
        #
        # @param relation [ActiveRecord::Relation] a batch of the table's rows, for example a background
        #   operation's sub-batch
        # @return [Counts] the outcome of the rows
        def reencrypt(relation)
          rows = table.filter(relation).pluck(*table.key_columns, *table.columns) # rubocop:disable CodeReuse/ActiveRecord -- generic over every table with encrypted columns

          rows.sum(Counts.zero) do |row|
            key_values = table.key_columns.zip(row).to_h
            stored = table.columns.zip(row.drop(table.key_columns.size)).to_h

            reencrypt_row(key_values, stored)
          end
        end

        private

        attr_reader :table, :dry_run, :reported_failures

        def reencrypt_row(key_values, stored)
          new_values, failed = new_values_for(key_values, stored)
          outcome = write_outcome(key_values, stored, new_values)

          count(failed ? :error : outcome)
        end

        # A column that fails is reported and left as it is; the row's other columns are still
        # re-encrypted.
        def new_values_for(key_values, stored)
          failed = false

          new_values = table.encrypted_columns.each_with_object({}) do |column, values|
            values.merge!(column.reencrypt(stored.slice(*column.columns)) || {})
          rescue StandardError => e
            failed = true
            # The error can quote the decrypted value, for example a JSON::ParserError
            error = ColumnError.new("#{table.name} couldn't re-encrypt #{column.columns.first} (#{e.class.name})")
            error.set_backtrace(e.backtrace)
            track_failure(error, key_values, column.columns, kind: e.class)
          end

          [new_values, failed]
        end

        def write_outcome(key_values, stored, new_values)
          return :skipped if new_values.empty?
          return :reencrypted if dry_run

          write(key_values, stored, new_values)
        end

        def write(key_values, stored, new_values)
          updated = within_savepoint do
            table.scope
              .where(key_values) # rubocop:disable CodeReuse/ActiveRecord -- generic over every table with encrypted columns
              .where(stored.slice(*new_values.keys)) # rubocop:disable CodeReuse/ActiveRecord -- compare-and-swap
              .update_all(new_values)
          end

          updated == 1 ? :reencrypted : :conflict
        rescue ActiveRecord::StatementInvalid => e
          raise unless quotes_values?(e)

          # The database error quotes the new values, or the whole row
          error = e.class.new("#{table.name} rejected the re-encrypted values (#{(e.cause || e).class.name})")
          error.set_backtrace(e.backtrace)
          # A NOT NULL or foreign key violation is a bug, not a row to skip
          raise error, cause: nil unless rejected_values?(e)

          track_failure(error, key_values, new_values.keys)
          :error
        end

        # Errors whose detail quotes the new values or the whole row. Others, such as timeouts, are
        # raised as they are.
        def quotes_values?(error)
          rejected_values?(error) || error.cause.is_a?(PG::IntegrityConstraintViolation)
        end

        # A unique index, a CHECK constraint or the column type rejected the new values.
        def rejected_values?(error)
          error.is_a?(ActiveRecord::RecordNotUnique) || error.is_a?(ActiveRecord::ValueTooLong) ||
            error.cause.is_a?(PG::CheckViolation) || error.cause.is_a?(PG::DataException)
        end

        # A rejected write would abort the caller's transaction, if there is one, so it's isolated
        # in a savepoint. Without a transaction, the write stays a single statement.
        def within_savepoint(&block)
          return yield unless table.model.connection.transaction_open?

          table.model.transaction(requires_new: true, &block)
        end

        # Only the first failure of each kind is reported, so that a column no key decrypts doesn't
        # report every row. The counts include them all.
        def track_failure(exception, key_values, columns, kind: exception.class)
          return unless reported_failures.add?([kind, columns])

          Gitlab::ErrorTracking.track_exception(
            exception,
            table_name: table.name,
            record_id: key_values[primary_key],
            columns: columns
          )
        end

        def count(outcome)
          Counts.zero.tap { |counts| counts[outcome] = 1 }
        end

        def primary_key
          table.key_columns.first
        end
      end
    end
  end
end
