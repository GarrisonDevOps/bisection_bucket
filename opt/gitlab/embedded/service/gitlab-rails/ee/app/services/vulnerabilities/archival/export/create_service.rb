# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Export
      class CreateService
        include Gitlab::Allowable

        def initialize(project, author, start_date, end_date, format:)
          @project = project
          @author = author
          @start_date = start_date
          @end_date = end_date
          @format = format
        end

        def execute
          authorize_author!

          schedule_export if archive_export.persisted?

          archive_export
        end

        private

        attr_reader :project, :author, :start_date, :end_date, :format

        def authorize_author!
          return if can?(author, :create_vulnerability_archive_export, project)

          raise Gitlab::Access::AccessDeniedError
        end

        def archive_export
          @archive_export ||= Vulnerabilities::ArchiveExport.create(
            project: project,
            author: author,
            date_range: date_range,
            format: format)
        end

        def schedule_export
          Vulnerabilities::Archival::Export::ExportWorker.perform_async(archive_export.id)
        end

        def date_range
          start_date..end_date
        end
      end
    end
  end
end
