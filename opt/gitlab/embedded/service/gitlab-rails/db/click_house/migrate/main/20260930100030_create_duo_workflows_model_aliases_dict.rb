# frozen_string_literal: true

class CreateDuoWorkflowsModelAliasesDict < ClickHouse::Migration
  # A String key needs a COMPLEX_KEY layout, so lookups pass a tuple:
  # dictGetOrDefault(..., tuple(model_used), model_used). Refreshes through LIFETIME
  # alone, since SYSTEM RELOAD DICTIONARY needs privileges the app user may lack.
  def up
    definition = <<~SQL
      CREATE DICTIONARY IF NOT EXISTS duo_workflows_model_aliases_dict
      (
          `model_used` String,
          `model_key` String,
          `hosting` String
      )
      PRIMARY KEY model_used
        SOURCE(
          CLICKHOUSE(
            QUERY '
              SELECT
                model_used,
                argMax(model_key, version) AS model_key,
                argMax(hosting, version) AS hosting
              FROM duo_workflows_model_aliases
              GROUP BY model_used
              HAVING argMax(deleted, version) = false
            '
          )
        )
        LIFETIME(MIN 300 MAX 600)
        LAYOUT(COMPLEX_KEY_HASHED())
    SQL

    create_dictionary(definition, source_tables: ['duo_workflows_model_aliases'])
  end

  def down
    execute('DROP DICTIONARY IF EXISTS duo_workflows_model_aliases_dict')
  end
end
