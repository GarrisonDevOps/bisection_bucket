# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      module UserExperienceSli
        # This middleware for Sidekiq-server rehydrates the current experiences
        # serialized to the job
        class Server
          def call(_worker_class, job, _queue)
            job[Labkit::UserExperienceSli::Current::AGGREGATION_KEY]&.each do |experience_id, data|
              xp = Labkit::UserExperienceSli::Current.rehydrate(experience_id, **data)
              xp.checkpoint(checkpoint_action: "sidekiq_job_started", worker: job["class"].to_s)
            end

            yield

          ensure
            Labkit::UserExperienceSli::Current.reset
          end
        end
      end
    end
  end
end
