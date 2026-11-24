# frozen_string_literal: true

module MergeTrains
  module MergeCommitMessage
    # TODO: Remove with GitLab 18.0, or whenever we can relatively
    # safely assume that no merge trains predating fast-forward merge
    # support exist.
    # See https://gitlab.com/gitlab-org/gitlab/-/issues/455421
    def self.legacy_value(merge_request, previous_ref)
      "Merge branch #{merge_request.source_branch} with #{previous_ref} " \
        "into #{merge_request.train_ref_path}"
    end
  end
end
