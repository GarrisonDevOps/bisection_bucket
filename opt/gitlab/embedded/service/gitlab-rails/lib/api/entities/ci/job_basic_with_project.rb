# frozen_string_literal: true

module API
  module Entities
    module Ci
      class JobBasicWithProject < Entities::Ci::JobBasic
        expose :project, using: ::API::Entities::ProjectIdentity,
          documentation: { type: 'API::Entities::ProjectIdentity' }
      end
    end
  end
end
