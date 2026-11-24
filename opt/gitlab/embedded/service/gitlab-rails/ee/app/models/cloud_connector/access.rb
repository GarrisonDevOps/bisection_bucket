# frozen_string_literal: true

module CloudConnector
  class Access < ApplicationRecord
    # Technically, access data has no expiration date, but we know that tokens
    # are good for at most 3 days currently, so this is a good estimate.
    STALE_PERIOD = 3.days

    ignore_column :data, remove_with: '18.6', remove_after: '2025-10-16'

    self.table_name = 'cloud_connector_access'
    validates :catalog, presence: true, json_schema: { filename: "cloud_connector_access_catalog" }, allow_nil: false
  end
end
