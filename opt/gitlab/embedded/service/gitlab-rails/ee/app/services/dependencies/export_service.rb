# frozen_string_literal: true

module Dependencies
  class ExportService
    EXPORTERS = {
      dependency_list: ::Sbom::Exporters::DependencyListService,
      sbom: ::Dependencies::ExportSerializers::Sbom::PipelineService,
      json_array: ::Sbom::Exporters::JsonArrayService,
      csv: ::Sbom::Exporters::CsvService,
      cyclonedx_1_6_json: ::Sbom::Exporters::Cyclonedx::V16JsonService
    }.freeze

    def self.execute(dependency_list_export)
      new(dependency_list_export).execute
    end

    def initialize(dependency_list_export)
      @dependency_list_export = dependency_list_export
    end

    def execute
      return unless dependency_list_export.created?

      create_export
      dependency_list_export.schedule_export_deletion
    end

    private

    attr_reader :dependency_list_export

    delegate :exportable, to: :dependency_list_export, private: true

    def create_export
      dependency_list_export.start!
      write_export_file
      dependency_list_export.finish!
      dependency_list_export.send_completion_email!
    rescue StandardError
      dependency_list_export.reset_state!

      raise
    end

    def write_export_file
      exporter.generate { |file| dependency_list_export.file = file }
      dependency_list_export.file.filename = filename
    end

    def exporter
      EXPORTERS[dependency_list_export.export_type.to_sym].new(dependency_list_export, sbom_occurrences)
    end

    def sbom_occurrences
      case exportable
      when ::Project
        ::Sbom::DependenciesFinder.new(exportable, params: default_filters).execute
      when ::Group
        exportable.sbom_occurrences.order_by_id
      end
    end

    def default_filters
      { source_types: default_source_type_filters }
    end

    def default_source_type_filters
      ::Sbom::Source::DEFAULT_SOURCES.keys + [nil]
    end

    def filename
      [
        exportable.class.name.demodulize.underscore,
        '_',
        exportable.id,
        '_dependencies_',
        Time.current.utc.strftime('%FT%H%M'),
        '.',
        file_extension
      ].join
    end

    def file_extension
      case dependency_list_export.export_type
      when 'sbom', 'cyclonedx_1_6_json'
        'cdx.json'
      when 'dependency_list', 'json_array'
        'json'
      when 'csv'
        'csv'
      end
    end
  end
end
