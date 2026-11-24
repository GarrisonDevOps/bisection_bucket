# frozen_string_literal: true

class PrepareEventsShardingKeyConstraintValidation < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  TABLE_NAME = :events
  CONSTRAINT_NAME = 'check_5766fc2949'

  def up
    prepare_async_check_constraint_validation TABLE_NAME, name: CONSTRAINT_NAME
  end

  def down
    unprepare_async_check_constraint_validation TABLE_NAME, name: CONSTRAINT_NAME
  end
end
