# frozen_string_literal: true

module ClickHouse
  # Newer ClickHouse versions quote the Null engine and keep the parens around a single-column
  # PRIMARY KEY or ORDER BY as written, so the dumped schema would differ between versions.
  # ClickHouse 25.x also formats some views as `AS WITH cte AS` where 26.x puts the CTE on its own line.
  module SchemaDumpNormalizer
    SINGLE_COLUMN_KEY = /(PRIMARY KEY|ORDER BY) \(([^(),\s]+)\)(?=[\s;),]|\z)/
    SINGLE_COLUMN_KEY_EXPRESSION = /\A\(([^(),\s]+)\)\z/
    INLINE_VIEW_CTE = /^AS WITH (\w+) AS$/

    def self.normalize(sql)
      return sql if sql.blank?

      sql
        .gsub('ENGINE = `Null`', 'ENGINE = Null')
        .gsub(/\A`Null`\z/, 'Null')
        .gsub(SINGLE_COLUMN_KEY, '\1 \2')
        .gsub(INLINE_VIEW_CTE, "AS WITH\n    \\1 AS")
    end

    # For the primary_key and sorting_key columns of system.tables
    def self.normalize_key(expression)
      return expression if expression.blank?

      expression.sub(SINGLE_COLUMN_KEY_EXPRESSION, '\1')
    end
  end
end
