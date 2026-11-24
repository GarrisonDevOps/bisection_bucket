# frozen_string_literal: true

module Import
  module AfterExportStrategies
    class CustomTemplateExportImportStrategy < BaseAfterExportStrategy
      include ::Gitlab::Utils::StrongMemoize
      include ::Gitlab::TemplateHelper

      validates :export_into_project_id, presence: true

      attr_reader :params

      def initialize(export_into_project_id:)
        super

        @params = {}
      end

      protected

      def strategy_execute
        return unless export_into_project_exists?

        prepare_template_environment(export_file, current_user)

        set_import_attributes
        attach_template_to_new_project

        ::RepositoryImportWorker.new.perform(export_into_project_id)
      ensure
        export_file.close if export_file.respond_to?(:close)
      end

      def export_file
        project.export_file(current_user)&.file
      end
      strong_memoize_attr :export_file

      def set_import_attributes
        ::Project.update(export_into_project_id, params.except(:import_export_upload))
      end

      def attach_template_to_new_project
        import_export_upload = params[:import_export_upload]
        import_export_upload.project_id = export_into_project_id
        import_export_upload.save!
      rescue ActiveRecord::RecordInvalid
        destination_project.import_state.mark_as_failed(
          import_export_upload.errors.full_messages.to_sentence
        )

        raise
      end

      # rubocop: disable CodeReuse/ActiveRecord -- override predates class move
      def export_into_project_exists?
        ::Project.exists?(export_into_project_id)
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def destination_project
        ::Project.find_by_id(export_into_project_id)
      end
      strong_memoize_attr :destination_project
    end
  end
end
