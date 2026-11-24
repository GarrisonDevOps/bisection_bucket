# frozen_string_literal: true

module API
  module Entities
    class DependencyListExport < Grape::Entity
      include ::API::Helpers::RelatedResourcesHelpers

      expose :id, documentation: { type: 'Integer', format: 'int64' }
      expose :status_name, as: :status, documentation: { type: 'String' }
      expose :finished?, as: :has_finished, documentation: { type: 'Boolean' }
      expose :export_type, documentation: { type: 'String' }
      expose :send_email, documentation: { type: 'Boolean' }
      expose :expires_at, documentation: { type: 'DateTime' }

      expose :self, documentation: { type: 'String' } do |export|
        expose_url api_v4_dependency_list_exports_path(export_id: export.id)
      end
      expose :download, documentation: { type: 'String' } do |export|
        expose_url api_v4_dependency_list_exports_download_path(export_id: export.id)
      end
    end
  end
end
