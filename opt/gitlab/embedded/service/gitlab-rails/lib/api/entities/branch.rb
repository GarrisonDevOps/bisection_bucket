# frozen_string_literal: true

module API
  module Entities
    class Branch < Grape::Entity
      include Gitlab::Routing

      expose :name, documentation: { type: 'String', example: 'master', desc: 'Name of the branch.' }

      expose :commit, using: ::API::Entities::Commit, documentation: { type: '::API::Entities::Commit', desc: 'Latest commit on the branch.' } do |repo_branch, options|
        options[:project].repository.commit(repo_branch.dereferenced_target)
      end

      expose :merged,
        documentation: {
          type: 'Boolean',
          example: true,
          desc: 'Whether the branch is merged into the default branch.'
        } do |repo_branch, options|
        if options[:merged_branch_names]
          options[:merged_branch_names].include?(repo_branch.name)
        else
          options[:project].repository.merged_to_root_ref?(repo_branch)
        end
      end

      expose :protected,
        documentation: {
          type: 'Boolean',
          example: true,
          desc: 'Whether the branch is protected.'
        } do |repo_branch, options|
        ::ProtectedBranch.protected?(options[:project], repo_branch.name)
      end

      expose :developers_can_push,
        documentation: {
          type: 'Boolean',
          example: true,
          desc: 'Whether a protected branch rule allows the Developer role to push to the branch.'
        } do |repo_branch, options|
        ::ProtectedBranch.developers_can?(:push, repo_branch.name, protected_refs: options[:project].all_protected_branches)
      end

      expose :developers_can_merge,
        documentation: {
          type: 'Boolean',
          example: true,
          desc: 'Whether a protected branch rule allows the Developer role to merge to the branch.'
        } do |repo_branch, options|
        ::ProtectedBranch.developers_can?(:merge, repo_branch.name, protected_refs: options[:project].all_protected_branches)
      end

      expose :can_push,
        documentation: {
          type: 'Boolean',
          example: true,
          desc: 'Whether the authenticated user can push to the branch.'
        } do |repo_branch, options|
        Gitlab::UserAccess.new(options[:current_user], container: options[:project]).can_push_to_branch?(repo_branch.name)
      end

      expose :default,
        documentation: {
          type: 'Boolean',
          example: true,
          desc: 'Whether the branch is the default branch of the project.'
        } do |repo_branch, options|
        options[:project].default_branch == repo_branch.name
      end

      expose :web_url,
        documentation: {
          type: 'String',
          example: 'https://gitlab.example.com/Commit921/the-dude/-/tree/master',
          desc: 'URL of the branch in the GitLab UI.'
        } do |repo_branch|
        project_tree_url(options[:project], repo_branch.name)
      end
    end
  end
end
