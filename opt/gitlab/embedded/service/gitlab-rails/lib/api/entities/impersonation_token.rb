# frozen_string_literal: true

module API
  module Entities
    class ImpersonationToken < Entities::PersonalAccessToken
      expose :impersonation, documentation: { type: 'Boolean', example: true }
    end
  end
end
