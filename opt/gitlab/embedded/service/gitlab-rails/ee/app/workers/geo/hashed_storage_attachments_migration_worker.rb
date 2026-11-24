# frozen_string_literal: true

module Geo
  class HashedStorageAttachmentsMigrationWorker # rubocop:disable Scalability/IdempotentWorker
    include ApplicationWorker

    data_consistency :always

    include GeoQueue

    loggable_arguments 1, 2

    def perform(_project_id, _old_attachments_path, _new_attachments_path)
      # no-op
    end
  end
end
