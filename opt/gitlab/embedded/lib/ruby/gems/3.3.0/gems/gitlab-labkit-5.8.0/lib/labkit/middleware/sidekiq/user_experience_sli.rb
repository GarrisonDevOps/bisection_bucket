# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      # This module contains all the sidekiq middleware regarding user
      # experience SLIs
      module UserExperienceSli
        autoload :Client, "labkit/middleware/sidekiq/user_experience_sli/client"
        autoload :Server, "labkit/middleware/sidekiq/user_experience_sli/server"
      end

      # Backward compatibility alias
      CoveredExperience = UserExperienceSli
    end
  end
end
