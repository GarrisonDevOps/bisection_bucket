# frozen_string_literal: true

module Vulnerabilities
  class ConsistencyCheckWorker
    include ApplicationWorker

    data_consistency :sticky
    feature_category :vulnerability_management

    idempotent!

    def perform(check_class_name, project_id)
      project = Project.find_by_id(project_id)

      return if project.blank?

      check_class_name.constantize.execute(project)

      Gitlab::AppLogger.info(
        message: 'Consistency check executed',
        class_name: check_class_name,
        gl_project_id: project_id,
        gl_project_path: project.full_path
      )
    end
  end
end
