# frozen_string_literal: true

module API
  module Entities
    class Compare < Grape::Entity
      expose :commit, using: ::API::Entities::Commit, documentation: {
        type: '::API::Entities::Commit', desc: 'Latest commit in the comparison.'
      } do |compare, options|
        commit_collection(compare, options).last
      end

      expose :commits, using: ::API::Entities::Commit,
        documentation: {
          type: '::API::Entities::Commit', is_array: true,
          desc: 'Commits between the two references. Not truncated when `compare_timeout` is `true`. For ' \
            'unauthenticated requests, contains at most the 100 most recent commits in the range. Behind a ' \
            'feature flag named `compare_api_anonymous_commits_limit`, disabled by default.'
        } do |compare, options|
        commit_collection(compare, options)
      end

      expose :diffs, using: ::API::Entities::Diff,
        documentation: {
          type: '::API::Entities::Diff', is_array: true, desc: 'File differences between the two references.'
        } do |compare, _|
        diff_collection(compare).to_a
      end

      expose :compare_timeout, documentation: {
        type: 'Boolean',
        desc: 'If `true`, the comparison exceeded size limits or timed out, and `diffs` might be incomplete.'
      } do |compare, _|
        diff_collection(compare).overflow?
      end

      expose :same, as: :compare_same_ref, documentation: {
        type: 'Boolean', desc: 'If `true`, `from` and `to` resolve to the same commit.'
      }

      expose :web_url,
        documentation: {
          type: 'String',
          example: "https://gitlab.example.com/gitlab/gitlab-foss/-/compare/main...feature",
          desc: 'URL to view the comparison in the GitLab UI.'
        } do |compare, _|
        Gitlab::UrlBuilder.build(compare)
      end

      private

      # Compare#commits(limit:) is not memoized, so without this `commit` and `commits` each make a ListCommits RPC.
      def commit_collection(compare, options)
        @commit_collection ||= compare.commits(limit: options[:commits_limit])
      end

      # Compare#diffs builds a new collection on every call, and each one makes its own CommitDiff RPC.
      def diff_collection(compare)
        @diff_collection ||= compare.diffs.diffs
      end
    end
  end
end
