# frozen_string_literal: true

module Gitlab
  module Database
    module Migrations
      class SwapColumns
        # A check constraint stays on the physical column it was created for, so after a swap a
        # constraint written for the retiring column guards the column that cleanup drops, and
        # PostgreSQL drops it along with the column without warning.
        #
        # Constraints are grouped by expression, reading each `*_convert_to_bigint` column as the
        # column it replaces. Before renaming anything, every group the swap touches must contain
        # a validated constraint that outlives cleanup, or the swap raises.
        #
        # One constraint per group carries the name the table started with. It belongs to the
        # constraint that reads the live column names, or when a multi-column conversion is half
        # done and none does, the one reading only bigint columns. The holder is worked out for
        # the names before and after the swap, and the two constraints exchange names if it moved.
        #
        # The name substitution is textual, so a column name inside a string literal is replaced
        # too. Writing one is contrived enough to leave unhandled.
        # See doc/development/database/avoiding_downtime_in_migrations.md.
        class CheckConstraints
          Column = Struct.new(:attnum, :name, :bigint, keyword_init: true)
          Constraint = Struct.new(:name, :expression, :normalized, :validated, :attnums, keyword_init: true)

          delegate :quote, :select_all, :say, :rename_constraint, :convert_to_bigint_column,
            to: :@migration_context

          def initialize(migration_context:, table:, column1:, column2:, skip: [])
            @migration_context = migration_context
            @table = table
            @column1 = column1.to_s
            @column2 = column2.to_s
            @skip = Array.wrap(skip).map(&:to_s)
          end

          # Raises when the swap would leave an expression without a validated constraint, and
          # returns the pairs of names to exchange once the columns have been renamed.
          def verify_and_plan_renames!
            verify_each_column_in_one_pair!
            verify_no_partition_local_constraints!
            verify_each_spans_one_column!
            verify_skipped_are_known!
            verify_every_expression_survives!

            affected_groups.filter_map { |group| planned_rename(group) }
          end

          def apply_renames(renames)
            renames.each do |losing, gaining|
              rename_constraint(@table, losing, :temp_name_for_renaming)
              rename_constraint(@table, gaining, losing)
              rename_constraint(@table, :temp_name_for_renaming, gaining)

              say "Moved check constraint #{losing} onto the constraint that outlives the swap"
            end
          end

          private

          # Only the expressions this swap can affect are considered. The rest keep whatever
          # constraints and names they already have.
          def affected_groups
            @affected_groups ||= constraints
              .group_by(&:normalized)
              .values
              .select { |group| group.any? { |c| c.attnums.intersect?(swapped_attnums) } }
          end

          def planned_rename(group)
            before = holder(group, names_before)
            after = holder(group, names_after)
            return if before.nil? || after.nil? || before == after

            [before.name, after.name]
          end

          # The constraint that should carry the name, given the column names in force. Halfway
          # through a multi-column conversion no constraint reads only live names, so the one
          # reading only bigint columns is the fallback.
          def holder(group, column_names)
            live = group.select { |c| reads_only_live_names?(c, column_names) }
            return live.first if live.one?

            surviving = group.select { |c| reads_only_surviving_columns?(c) }
            surviving.first if surviving.one?
          end

          # A constraint outlives the conversion when cleanup drops none of its columns: it
          # reads only the names the application uses, or only the bigint member of each pair.
          def outlives?(constraint, column_names)
            reads_only_live_names?(constraint, column_names) || reads_only_surviving_columns?(constraint)
          end

          def reads_only_live_names?(constraint, column_names)
            constraint.attnums.none? { |attnum| conversion_names.include?(column_names.fetch(attnum)) }
          end

          def reads_only_surviving_columns?(constraint)
            constraint.attnums.all? do |attnum|
              paired_attnums.exclude?(attnum) || surviving_attnums.include?(attnum)
            end
          end

          def verify_every_expression_survives!
            failing = affected_groups.reject do |group|
              group.any? { |c| @skip.include?(c.name) } ||
                group.any? { |c| c.validated && outlives?(c, names_after) }
            end
            return if failing.empty?

            raise_swap_error(
              "#{failing.size} check constraint expression(s) would be left without a " \
                "validated constraint once the conversion columns are dropped, because " \
                "PostgreSQL drops a check constraint along with its column.\n\n" \
                "#{failing.map { |group| missing_survivor_details(group) }.join("\n\n")}\n\n" \
                "Pass `skip_check_constraint_verification: " \
                "%w[#{failing.map { |group| dropped_by_cleanup(group).name }.join(' ')}]` to `swap_columns` " \
                "to swap anyway."
            )
          end

          # The constraint the documentation tells authors to name when excluding a group.
          def dropped_by_cleanup(group)
            group.find { |c| !outlives?(c, names_after) } || group.first
          end

          def missing_survivor_details(group)
            candidate = group.find { |c| outlives?(c, names_after) }

            reason =
              if candidate
                "#{candidate.name} would outlive the swap but is NOT VALID. Validate it in an " \
                  "earlier migration."
              else
                "Add `#{suggested_expression(group.first.normalized)}` as NOT VALID, then " \
                  "validate it, in earlier migrations."
              end

            "  #{group.map(&:name).join(', ')}: #{group.first.expression}\n  #{reason}"
          end

          # The expression an author has to add: the same check, reading the column of each
          # pair that keeps its data, under the name that column has right now.
          def suggested_expression(normalized)
            surviving_by_canonical.reduce(normalized) do |expression, (canonical, surviving)|
              expression.gsub(/\b#{Regexp.escape(canonical.name)}\b/, surviving.name)
            end
          end

          # Every pair on the table is read under one name, not only the pair being swapped,
          # because `num_nonnulls(group_id, project_id)` matches its counterpart only once both
          # columns are read the same way.
          def normalize(expression)
            column_pairs.reduce(expression) do |normalized, (canonical, temp)|
              normalized.gsub(/\b#{Regexp.escape(temp.name)}\b/, canonical.name)
            end
          end

          # Pairs are [column the application uses, its `*_convert_to_bigint` column], found
          # through `convert_to_bigint_column` rather than a suffix match. The pair being
          # swapped is always included, because `swap_columns` is not limited to conversions.
          def column_pairs
            @column_pairs ||= begin
              by_name = table_columns.index_by(&:name)

              found = table_columns.filter_map do |column|
                temp = by_name[convert_to_bigint_column(column.name)]

                [column, temp] if temp
              end

              swapped = [by_name.fetch(@column1), by_name.fetch(@column2)]

              (found + [swapped]).uniq { |pair| pair.map(&:attnum).sort }
            end
          end

          # A column in two pairs would be read under two names at once, so the comparison
          # could not tell which constraint reads which column.
          def verify_each_column_in_one_pair!
            repeated = column_pairs.flatten.group_by(&:attnum).values.select(&:many?)
            return if repeated.empty?

            raise_swap_error(
              "column(s) #{repeated.map { |c| c.first.name }.join(', ')} belong to more than " \
                "one conversion pair. Swap each column with its `*_convert_to_bigint` counterpart."
            )
          end

          # The column of each pair that keeps its data, which is the one holding the bigint
          # type. A swap that is not a bigint conversion has no such column, so the second
          # argument is taken to be the one that survives.
          def surviving_by_canonical
            @surviving_by_canonical ||= column_pairs.to_h do |canonical, temp|
              [canonical, canonical.bigint && !temp.bigint ? canonical : temp]
            end
          end

          def surviving_attnums
            @surviving_attnums ||= surviving_by_canonical.values.map(&:attnum).to_set
          end

          def paired_attnums
            @paired_attnums ||= column_pairs.flatten.map(&:attnum).to_set
          end

          def conversion_names
            @conversion_names ||= column_pairs.map { |_, temp| temp.name }.to_set
          end

          def swapped_attnums
            @swapped_attnums ||= [@column1, @column2]
              .map { |name| table_columns_by_name.fetch(name).attnum }.to_set
          end

          def names_before
            @names_before ||= table_columns.to_h { |column| [column.attnum, column.name] }
          end

          # The swap exchanges the two names, so a constraint reads the other one afterwards.
          def names_after
            @names_after ||= begin
              first = table_columns_by_name.fetch(@column1)
              second = table_columns_by_name.fetch(@column2)

              names_before.merge(first.attnum => second.name, second.attnum => first.name)
            end
          end

          def table_columns_by_name
            @table_columns_by_name ||= table_columns.index_by(&:name)
          end

          # Read from the catalog rather than from the schema cache, which `swap_columns` only
          # clears before each rename and so can be stale by the second call in a migration.
          def table_columns
            @table_columns ||= begin
              rows = select_all(<<~SQL)
                SELECT a.attnum, a.attname AS name, (a.atttypid = 'bigint'::regtype) AS bigint
                FROM pg_attribute a
                WHERE a.attrelid = #{quoted_table} AND a.attnum > 0 AND NOT a.attisdropped
                ORDER BY a.attnum
              SQL

              rows.map do |row|
                Column.new(attnum: row['attnum'], name: row['name'], bigint: row['bigint'])
              end
            end
          end

          # `conkey` is read as text, because an array column comes back from the adapter
          # undecoded and would silently match nothing.
          def constraints
            @constraints ||= begin
              rows = select_all(<<~SQL)
                SELECT c.conname AS name,
                       c.convalidated AS validated,
                       pg_get_expr(c.conbin, c.conrelid) AS expression,
                       array_to_string(c.conkey, ',') AS attnums
                FROM pg_constraint c
                WHERE c.conrelid = #{quoted_table} AND c.contype = 'c'
                ORDER BY c.conname
              SQL

              rows.map do |row|
                Constraint.new(
                  name: row['name'],
                  expression: row['expression'],
                  normalized: normalize(row['expression']),
                  validated: row['validated'],
                  attnums: row['attnums'].to_s.split(',').map(&:to_i).to_set
                )
              end
            end
          end

          # An entry that matches nothing is a typo or a leftover from an earlier revision, and
          # silently ignoring it would hide whichever constraint it was meant to cover.
          def verify_skipped_are_known!
            unknown = @skip - constraints.map(&:name)
            return if unknown.empty?

            raise_swap_error(
              "#{unknown.join(', ')} passed to `skip_check_constraint_verification` " \
                "did not match a check constraint on #{@table}. Remove the entry, or correct " \
                "the name."
            )
          end

          # A constraint declared on a partition has no row on the parent, so the rename would
          # leave it on the column cleanup drops. It is reported rather than handled, because
          # a partition's attribute numbers may differ from the parent's.
          def verify_no_partition_local_constraints!
            names = select_all(<<~SQL).rows.flatten
              SELECT DISTINCT c.conrelid::regclass::text || '.' || c.conname
              FROM pg_partition_tree(#{quoted_table}) t
              JOIN pg_constraint c ON c.conrelid = t.relid AND c.contype = 'c' AND c.conislocal
              JOIN pg_attribute a ON a.attrelid = c.conrelid
                AND a.attnum = ANY (c.conkey) AND NOT a.attisdropped
              WHERE t.relid <> #{quoted_table}
                AND a.attname IN (#{quote(@column1)}, #{quote(@column2)})
            SQL
            return if names.empty?

            raise_swap_error(
              "check constraint(s) #{names.join(', ')} are declared on a partition rather " \
                "than on #{@table}, so they cannot be handled here. Recreate them on " \
                "#{@table}, or drop and recreate them around the swap."
            )
          end

          # One constraint covering both columns cannot be split between them, so neither
          # column can keep it after the swap.
          def verify_each_spans_one_column!
            names = constraints
              .select { |c| swapped_attnums.subset?(c.attnums) }
              .map(&:name) - @skip
            return if names.empty?

            raise_swap_error(
              "check constraint(s) #{names.join(', ')} reference both columns. Rewrite them " \
                "to reference one column, or drop and recreate them around the swap."
            )
          end

          def raise_swap_error(message)
            raise "Cannot swap columns #{@column1} and #{@column2} " \
              "on #{@table}: #{message}"
          end

          def quoted_table
            "#{quote(@table.to_s)}::regclass"
          end
        end
      end
    end
  end
end
