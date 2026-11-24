# frozen_string_literal: true

module API
  module Entities
    class GroupScimAuthAccessToken < ScimAccessTokenBase
      expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
    end
  end
end
