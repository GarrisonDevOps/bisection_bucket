# frozen_string_literal: true

module API
  module Entities
    class MergeRequestDiff < Grape::Entity
      expose :id,
        documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the merge request diff version.' }
      expose :head_commit_sha,
        documentation: { type: 'String', example: '1234abcd', desc: 'SHA of the head commit of the source branch.' }
      expose :base_commit_sha,
        documentation: {
          type: 'String', example: '1234abcd', desc: 'SHA of the merge-base commit of the source and target branches.'
        }
      expose :start_commit_sha,
        documentation: {
          type: 'String', example: '1234abcd',
          desc: 'SHA of the head commit of the target branch when this diff version was created.'
        }
      expose :created_at,
        documentation: {
          type: 'DateTime', example: '2022-01-31T15:10:45.080Z', desc: 'Timestamp of when the diff version was created.'
        }
      expose :merge_request_id,
        documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the merge request.' }
      expose :state,
        documentation: {
          type: 'String', example: 'collected',
          desc: 'State of the merge request diff. Can be `empty`, `collected`, `overflow` or `without_files`. ' \
            'Deprecated values: `timeout`, `overflow_commits_safe_size`, `overflow_diff_files_limit` and ' \
            '`overflow_diff_lines_limit`.'
        }
      expose :real_size, documentation: { type: 'String', example: '1', desc: 'Number of changes in the diff version.' }
      expose :patch_id_sha,
        documentation: { type: 'String', example: '1234abcd',
                         desc: 'Patch ID of the diff version, from `git patch-id`.' }
    end
  end
end
