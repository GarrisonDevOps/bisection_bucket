# frozen_string_literal: true

class SwapCiUsedMinutesByRunnerDailyTables < ClickHouse::Migration
  TABLE = 'ci_used_minutes_by_runner_daily'
  NEW_TABLE = 'ci_used_minutes_by_runner_daily_v2'

  def up
    return if project_id_in_primary_key?

    safe_table_swap(TABLE, NEW_TABLE)
  end

  def down
    return unless project_id_in_primary_key?

    safe_table_swap(TABLE, NEW_TABLE)
  end

  private

  def project_id_in_primary_key?
    query = ClickHouse::Client::Query.new(
      raw_query: <<~SQL,
        SELECT has(splitByString(', ', primary_key), 'project_id') AS has_project_id
        FROM system.tables
        WHERE database = {database:String} AND name = {table:String}
      SQL
      placeholders: { database: connection.database_name, table: TABLE }
    )

    connection.select(query).first&.fetch('has_project_id').to_i == 1
  end
end
