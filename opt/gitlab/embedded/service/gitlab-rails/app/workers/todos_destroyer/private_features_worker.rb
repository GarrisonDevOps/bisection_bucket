# frozen_string_literal: true

module TodosDestroyer
  class PrivateFeaturesWorker
    include ApplicationWorker

    data_consistency :always

    sidekiq_options retry: 3
    include TodosDestroyerQueue

    idempotent!
    deduplicate :until_executing, including_scheduled: true

    def perform(project_id, user_id = nil)
      ::Todos::Destroy::UnauthorizedFeaturesService.new(project_id, user_id).execute
    end
  end
end
