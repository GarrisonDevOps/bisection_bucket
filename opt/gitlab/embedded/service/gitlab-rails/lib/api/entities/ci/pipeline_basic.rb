# frozen_string_literal: true

module API
  module Entities
    module Ci
      class PipelineBasic < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the pipeline.' }
        expose :iid, documentation: { type: 'Integer', example: 2, desc: 'Internal ID of the pipeline.' }
        expose :project_id,
          documentation: { type: 'Integer', format: 'int64', example: 3, desc: 'ID of the project of the pipeline.' }
        expose :sha, documentation: { type: 'String', example: '0ec9e58fdfca6cdd6652c083c9edb53abc0bad52',
                                      desc: 'SHA of the commit the pipeline runs for.' }
        expose :ref,
          documentation: { type: 'String', example: 'feature-branch', desc: 'Git reference of the pipeline.' }
        expose :status, documentation: { type: 'String', example: 'success', desc: 'Status of the pipeline.' }
        expose :source, documentation: { type: 'String', example: 'push', desc: 'Source that triggered the pipeline.' }
        expose :created_at, documentation: { type: 'DateTime', example: '2022-10-21T16:49:48.000+02:00',
                                             desc: 'Timestamp when the pipeline was created.' }
        expose :updated_at, documentation: { type: 'DateTime', example: '2022-10-21T16:49:48.000+02:00',
                                             desc: 'Timestamp when the pipeline was last updated.' }

        expose :web_url,
          documentation: {
            type: 'String',
            example: 'https://gitlab.example.com/gitlab-org/gitlab-foss/-/pipelines/61',
            desc: 'URL of the pipeline in the GitLab UI.'
          } do |pipeline, _options|
          Gitlab::Routing.url_helpers.project_pipeline_url(pipeline.project, pipeline)
        end
      end
    end
  end
end
