# frozen_string_literal: true

class AddDeletedOnToMlModels < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :ml_models, :deleted_on, :datetime_with_timezone
  end
end
