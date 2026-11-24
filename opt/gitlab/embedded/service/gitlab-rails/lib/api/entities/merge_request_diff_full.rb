# frozen_string_literal: true

module API
  module Entities
    class MergeRequestDiffFull < MergeRequestDiff
      expose :commits, using: ::API::Entities::Commit,
        documentation: {
          type: '::API::Entities::Commit', is_array: true, desc: 'Commits in the diff version.'
        } do |diff, _|
        diff.commits(load_from_gitaly: true)
      end

      expose :diffs, using: ::API::Entities::Diff,
        documentation: {
          type: '::API::Entities::Diff', is_array: true, desc: 'Diffs in the diff version.'
        } do |compare, _|
        compare.raw_diffs(limits: false).to_a
      end
    end
  end
end
