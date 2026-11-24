# frozen_string_literal: true

require "active_support"
require "labkit/user_experience_sli/experience"

module Labkit
  module UserExperienceSli
    # The `Current` class represents a container for the current set
    # of `Labkit::UserExperienceSli::Experience` instances started and
    # not yet completed.
    #
    # It uses `ActiveSupport::CurrentAttributes` to provide a thread-safe way to
    # store and access experiences throughout the request and background job lifecycle.
    #
    # Example usage:
    #   Labkit::UserExperienceSli::Current.active_experiences << my_experience
    #   Labkit::UserExperienceSli::Current.rehydrate("create_merge_request", "start_time" => "2025-08-22T10:02:15.237Z")
    class Current < ActiveSupport::CurrentAttributes
      AGGREGATION_KEY = 'labkit_user_experiences'

      attribute :_active_experiences

      def active_experiences
        self._active_experiences ||= {}
      end

      def rehydrate(experience_id, **data)
        instance = Labkit::UserExperienceSli.get(experience_id).rehydrate(data)
        active_experiences[instance.id] = instance
        instance
      end
    end
  end
end
