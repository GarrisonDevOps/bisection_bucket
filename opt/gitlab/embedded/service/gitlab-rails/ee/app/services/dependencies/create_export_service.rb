# frozen_string_literal: true

module Dependencies
  class CreateExportService
    include Gitlab::Utils::StrongMemoize
    include Gitlab::InternalEventsTracking

    ALLOWED_PARAMS = %i[
      export_type
      send_email
    ].freeze

    def initialize(exportable, author, params)
      @exportable = exportable
      @author = author
      @params = params
    end

    attr_reader :author, :exportable, :params

    def execute
      if dependency_list_export.persisted?
        Dependencies::ExportWorker.perform_async(dependency_list_export.id)

        track_export_creation

        ServiceResponse.success(payload: { dependency_list_export: dependency_list_export })
      else
        ServiceResponse.error(message: dependency_list_export.errors.full_messages)
      end
    end

    private

    def dependency_list_export
      Dependencies::DependencyListExport.create(
        exportable: exportable,
        author: author,
        **create_params
      )
    end
    strong_memoize_attr :dependency_list_export

    def create_params
      params.slice(*ALLOWED_PARAMS)
    end

    def track_export_creation
      project = dependency_list_export.project

      track_internal_event(
        'create_dependency_list_export',
        user: author,
        project: project,
        namespace: dependency_list_export.group || project&.namespace,
        additional_properties: {
          label: dependency_list_export.export_type,
          property: exportable.class.name
        }
      )
    end
  end
end
