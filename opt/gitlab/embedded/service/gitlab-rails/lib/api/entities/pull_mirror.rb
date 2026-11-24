# frozen_string_literal: true

module API
  module Entities
    class PullMirror < Grape::Entity
      expose :id, documentation: {
        type: 'Integer', format: 'int64', example: 101486, desc: 'ID of the mirror configuration.'
      }
      expose :status, as: :update_status, documentation: {
        type: 'String', example: 'finished',
        desc: 'Status of the mirror update. One of `none`, `scheduled`, `started`, `finished`, `failed`, ' \
          'or `canceled`.'
      }
      expose :url,
        documentation: { type: 'String',
                         example: 'https://*****:*****@gitlab.com/gitlab-org/security/gitlab.git',
                         desc: 'URL of the mirrored repository, with credentials masked.' } do |import_state|
        import_state.project.safe_import_url
      end
      expose :last_error, documentation: {
        type: 'String', example: nil, desc: 'Most recent error message. `null` if no error occurred.'
      }
      expose :last_update_at, documentation: {
        type: 'DateTime', example: '2020-01-06T17:32:02.823Z',
        desc: 'Timestamp of the most recent mirror update attempt.'
      }
      expose :last_update_started_at, documentation: {
        type: 'DateTime', example: '2020-01-06T17:32:02.823Z', desc: 'Timestamp when the last mirror update started.'
      }
      expose :last_successful_update_at, documentation: {
        type: 'DateTime', example: '2020-01-06T17:32:02.823Z', desc: 'Timestamp of the last successful mirror update.'
      }
      expose :enabled, documentation: { type: 'Boolean', example: false, desc: 'If `true`, the mirror is active.' }
      expose :mirror_trigger_builds, documentation: {
        type: 'Boolean', example: false, desc: 'If `true`, mirror updates trigger pipelines.'
      }
      expose :only_mirror_protected_branches, documentation: {
        type: 'Boolean', example: false,
        desc: 'If `true`, only protected branches are mirrored. `null` if not set.'
      }
      expose :mirror_overwrites_diverged_branches, documentation: {
        type: 'Boolean', example: false, desc: 'If `true`, the mirror overwrites diverged branches.'
      }
      expose :mirror_branch_regex, documentation: {
        type: 'String', example: 'branch_name',
        desc: 'Regular expression that filters which branches are mirrored. `null` if not set.'
      }

      delegate :project, to: :object
      delegate :mirror_trigger_builds, :only_mirror_protected_branches, :mirror_overwrites_diverged_branches,
        :mirror_branch_regex, to: :project

      def enabled
        object.project.mirror
      end
    end
  end
end
