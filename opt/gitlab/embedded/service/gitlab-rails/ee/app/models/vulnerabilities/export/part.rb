# frozen_string_literal: true

module Vulnerabilities
  class Export
    class Part < ::SecApplicationRecord
      include FileStoreMounter

      self.table_name = "vulnerability_export_parts"

      mount_file_store_uploader AttachmentUploader

      belongs_to :vulnerability_export, class_name: "Vulnerabilities::Export"
      belongs_to :organization, class_name: "Organizations::Organization"

      validates :start_id, presence: true
      validates :end_id, presence: true

      scope :for_exports, ->(exports) { where(vulnerability_export_id: exports) }

      def retrieve_upload(_identifier, paths)
        Upload.find_by(model: self, path: paths)
      end

      def uploads_sharding_key
        { organization_id: organization_id }
      end
    end
  end
end
