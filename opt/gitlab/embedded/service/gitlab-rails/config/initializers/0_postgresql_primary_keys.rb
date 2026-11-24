# frozen_string_literal: true

# Adds patch for ActiveRecord `primary_keys` method
# to optimize the query for primary key retrieval.

# Rails commit: https://github.com/rails/rails/commit/c93d1b09fcc013033af506b10fd60829267be85c
# Issue: https://gitlab.com/gitlab-org/gitlab/-/work_items/579305
module PostgreSQLAdapterCustomPrimaryKeys
  def primary_keys(table_name)
    query_values(<<~SQL.squish, "SCHEMA")
      SELECT a.attname
      FROM pg_index i
      JOIN pg_attribute a
        ON a.attrelid = i.indrelid
        AND a.attnum = ANY(i.indkey)
        WHERE i.indrelid = #{quote(quote_table_name(table_name))}::regclass
        AND i.indisprimary
       ORDER BY array_position(i.indkey, a.attnum)
    SQL
  end
end

# Rails 8.1 ships the same query, so the patch only applies before it.
# TODO: Remove this file and its spec after upgrading to Rails >= 8.1.0
if Rails.gem_version < Gem::Version.new('8.1.0')
  ActiveRecord::ConnectionAdapters::PostgreSQLAdapter.prepend(PostgreSQLAdapterCustomPrimaryKeys)
end
