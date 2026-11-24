# frozen_string_literal: true

module Search
  class ProjectIndexIntegrityWorker
    include ApplicationWorker
    include Search::Worker
    prepend ::Geo::SkipSecondary

    data_consistency :delayed

    deduplicate :until_executed
    idempotent!
    urgency :throttled

    def perform(project_id, options = {})
      return if project_id.blank?

      project = Project.find_by_id(project_id)

      if project.nil?
        logger.warn(structured_payload(message: 'project not found', project_id: project_id))
        return
      end

      ::Search::IndexRepairService.execute(project, params: options.with_indifferent_access)
    end

    def logger
      @logger ||= ::Gitlab::Elasticsearch::Logger.build
    end
  end
end
