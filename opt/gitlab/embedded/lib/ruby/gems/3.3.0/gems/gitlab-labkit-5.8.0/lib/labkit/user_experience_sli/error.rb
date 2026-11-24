# frozen_string_literal: true

module Labkit
  module UserExperienceSli
    UserExperienceError = Class.new(StandardError)
    NotFoundError = Class.new(UserExperienceError)
    ReservedKeywordError = Class.new(UserExperienceError)
  end
end
