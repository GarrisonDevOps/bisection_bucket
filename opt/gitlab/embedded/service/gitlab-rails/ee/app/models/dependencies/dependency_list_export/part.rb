# frozen_string_literal: true

module Dependencies # rubocop:disable Gitlab/BoundedContexts -- This is an existing module
  class DependencyListExport
    class Part < ::SecApplicationRecord
      include FileStoreMounter
      include SafelyChangeColumnDefault

      columns_changing_default :organization_id

      self.table_name = 'dependency_list_export_parts'

      mount_file_store_uploader AttachmentUploader

      belongs_to :dependency_list_export, class_name: 'Dependencies::DependencyListExport'
      belongs_to :organization, class_name: 'Organizations::Organization'

      belongs_to :first_record, class_name: 'Sbom::Occurrence', foreign_key: :start_id # rubocop:disable Rails/InverseOf -- The inverse relation is not necessary
      belongs_to :last_record, class_name: 'Sbom::Occurrence', foreign_key: :end_id # rubocop:disable Rails/InverseOf -- The inverse relation is not necessary

      validates :start_id, presence: true
      validates :end_id, presence: true

      scope :for_exports, ->(exports) { where(dependency_list_export_id: exports) }

      def retrieve_upload(_identifier, paths)
        Upload.find_by(model: self, path: paths)
      end

      def sbom_occurrences
        exportable.sbom_occurrences
                  .in_parent_group_after_and_including(first_record)
                  .in_parent_group_before_and_including(last_record)
      end

      delegate :exportable, to: :dependency_list_export, private: true

      def uploads_sharding_key
        { organization_id: organization_id }
      end
    end
  end
end
