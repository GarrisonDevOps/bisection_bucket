# frozen_string_literal: true

module API
  module Entities
    class DiffRefs < Grape::Entity
      expose :base_sha,
        documentation: {
          type: 'String', example: 'b83d6e391c22777fca1ed3012fce84f633d7fed0',
          desc: 'SHA of the merge base commit where the source and target branches diverged.'
        }
      expose :head_sha,
        documentation: {
          type: 'String', example: 'b83d6e391c22777fca1ed3012fce84f633d7fed0',
          desc: 'SHA of the head commit of the source branch.'
        }
      expose :start_sha,
        documentation: {
          type: 'String', example: 'b83d6e391c22777fca1ed3012fce84f633d7fed0',
          desc: 'SHA of the target branch commit the diff starts from. Usually the same as `base_sha`.'
        }
    end
  end
end
