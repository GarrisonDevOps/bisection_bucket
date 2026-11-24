# frozen_string_literal: true

module API
  module Entities
    class ProjectJobTokenScope < Grape::Entity
      expose(:inbound_enabled, documentation: {
        type: 'Boolean',
        desc: 'If `true`, only groups and projects in the job token allowlist can access this project. ' \
          'Also `true` when the instance enforces the job token allowlist. If `false`, all projects have access.'
      }) do |project, _|
        project.ci_inbound_job_token_scope_enabled?
      end
      expose(:outbound_enabled, documentation: {
        type: 'Boolean',
        desc: 'If `true`, the CI/CD job token generated in this project can access only the projects in its ' \
          'outbound scope. Deprecated.'
      }) do |project, _|
        project.ci_outbound_job_token_scope_enabled?
      end
    end
  end
end
