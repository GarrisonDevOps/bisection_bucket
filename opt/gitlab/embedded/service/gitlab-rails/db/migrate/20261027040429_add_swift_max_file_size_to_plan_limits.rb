# frozen_string_literal: true

class AddSwiftMaxFileSizeToPlanLimits < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :plan_limits, :swift_max_file_size, :bigint, default: 100.megabytes, null: false
  end
end
