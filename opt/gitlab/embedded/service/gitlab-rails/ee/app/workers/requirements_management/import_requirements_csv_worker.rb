# frozen_string_literal: true

module RequirementsManagement
  class ImportRequirementsCsvWorker
    include ApplicationWorker

    data_consistency :always

    sidekiq_options retry: 3
    include Gitlab::Utils::StrongMemoize

    idempotent!
    feature_category :requirements_management

    sidekiq_retries_exhausted do |job|
      Upload.find_by_id(job['args'][2])&.destroy
    end

    def perform(current_user_id, project_id, upload_id)
      upload = Upload.find_by_id(upload_id)
      user = User.find_by_id(current_user_id)
      project = Project.find_by_id(project_id)

      return unless upload && user && project

      RequirementsManagement::ImportCsvService.new(user, project, upload.retrieve_uploader).execute
      upload.destroy!
    end
  end
end
