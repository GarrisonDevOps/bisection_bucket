# frozen_string_literal: true

require 'labkit/user_experience_sli/current'

module Labkit
  module Middleware
    module Sidekiq
      module UserExperienceSli
        # This middleware for Sidekiq-client wraps scheduling jobs with covered
        # experience context. It retrieves the current experiences and
        # populates the job with them.
        class Client
          def call(worker_class, job, _queue, _redis_pool)
            data = Labkit::UserExperienceSli::Current.active_experiences.inject({}) do |data, (_, xp)|
              xp.checkpoint(checkpoint_action: "sidekiq_job_scheduled", worker: worker_class.to_s)
              data.merge!(xp.to_h)
            end

            job[Labkit::UserExperienceSli::Current::AGGREGATION_KEY] = data unless data.empty?

            yield
          end
        end
      end
    end
  end
end
