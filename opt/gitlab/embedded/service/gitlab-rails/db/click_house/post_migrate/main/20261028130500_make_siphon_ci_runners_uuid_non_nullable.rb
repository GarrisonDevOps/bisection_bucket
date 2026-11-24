# frozen_string_literal: true

class MakeSiphonCiRunnersUuidNonNullable < ClickHouse::Migration
  ZERO_UUID = "toUUID('00000000-0000-0000-0000-000000000000')"

  def up
    # ClickHouse < 25.12 fails the type change on NULLs and can leave a stuck mutation, so replace them first.
    # mutations_sync = 2 makes the MODIFY wait for the UPDATE, which it would otherwise not do.
    execute_when_idle <<~SQL
      ALTER TABLE siphon_ci_runners UPDATE uuid = #{ZERO_UUID} WHERE uuid IS NULL
      SETTINGS mutations_sync = 2
    SQL

    execute_when_idle <<~SQL
      ALTER TABLE siphon_ci_runners MODIFY COLUMN uuid UUID DEFAULT #{ZERO_UUID}
    SQL
  end

  def down
    # Zero UUIDs written by `up` are not reverted to NULL: they carry the same "no uuid"
    # meaning, and reverting would need another data-rewriting mutation.
    execute_when_idle <<~SQL
      ALTER TABLE siphon_ci_runners MODIFY COLUMN uuid Nullable(UUID)
    SQL

    return unless column_default_present?('siphon_ci_runners', 'uuid')

    execute_when_idle <<~SQL
      ALTER TABLE siphon_ci_runners MODIFY COLUMN uuid REMOVE DEFAULT
    SQL
  end
end
