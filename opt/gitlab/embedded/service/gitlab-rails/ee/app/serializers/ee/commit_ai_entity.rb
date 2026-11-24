# frozen_string_literal: true

module EE
  class CommitAiEntity < ::CommitEntity
    expose :commit_comments do |_commit, options|
      options[:resource].notes_with_limit(notes_limit: options[:notes_limit])
    end

    expose :diffs do |_commit, options|
      options[:resource].resource.raw_diffs.as_json
    end
  end
end
