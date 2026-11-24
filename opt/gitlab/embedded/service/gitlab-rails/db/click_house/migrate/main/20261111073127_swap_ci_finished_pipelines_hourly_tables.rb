# frozen_string_literal: true

class SwapCiFinishedPipelinesHourlyTables < ClickHouse::Migration
  TABLE = 'ci_finished_pipelines_hourly'
  NEW_TABLE = 'ci_finished_pipelines_hourly_v2'

  def up
    return if name_in_primary_key?

    safe_table_swap(TABLE, NEW_TABLE)
  end

  def down
    return unless name_in_primary_key?

    safe_table_swap(TABLE, NEW_TABLE)
  end

  private

  def name_in_primary_key?
    query = ClickHouse::Client::Query.new(
      raw_query: <<~SQL,
        SELECT has(splitByString(', ', primary_key), 'name') AS has_name
        FROM system.tables
        WHERE database = {database:String} AND name = {table:String}
      SQL
      placeholders: { database: connection.database_name, table: TABLE }
    )

    connection.select(query).first&.fetch('has_name').to_i == 1
  end
end
