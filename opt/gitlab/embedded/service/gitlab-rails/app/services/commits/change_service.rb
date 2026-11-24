# frozen_string_literal: true

module Commits
  class ChangeService < Commits::CreateService
    def initialize(*args)
      super

      @commit = params[:commit]
      @message = params[:message]
    end

    def commit_message
      raise NotImplementedError
    end

    private

    attr_reader :commit

    def commit_change(action)
      message = @message || commit_message

      yield message
    rescue Gitlab::Git::Repository::CreateTreeError => ex
      raise ChangeError.new("#{failure_status(action)}: #{failure_detail(ex.error_code, action)}", ex.error_code)
    rescue Gitlab::Git::Repository::CommitNotFound
      # Happens when committing into a fork that does not contain the commit being reverted or cherry-picked.
      detail = s_("MergeRequests|The commit could not be found in the target repository. " \
        "Please perform this action locally.")

      raise ChangeError, "#{failure_status(action)}: #{detail}"
    end

    def failure_status(action)
      if @commit.merged_merge_request?(current_user)
        if action == :cherry_pick
          s_("MergeRequests|Merge request cherry-pick failed")
        else
          s_("MergeRequests|Merge request revert failed")
        end
      elsif action == :cherry_pick
        s_("MergeRequests|Commit cherry-pick failed")
      else
        s_("MergeRequests|Commit revert failed")
      end
    end

    def failure_detail(error_code, action)
      case [error_code, action]
      when [:conflict, :cherry_pick]
        format(s_("MergeRequests|These changes conflict with changes on %{branch_name}. " \
          "Cherry-pick locally to resolve the conflicts."), branch_name: @start_branch)
      when [:conflict, :revert]
        format(s_("MergeRequests|These changes conflict with changes on %{branch_name}. " \
          "Revert locally to resolve the conflicts."), branch_name: @start_branch)
      when [:empty, :cherry_pick]
        format(s_("MergeRequests|There is nothing to cherry-pick into %{branch_name}."), branch_name: @start_branch)
      when [:empty, :revert]
        format(s_("MergeRequests|There is nothing to revert in %{branch_name}."), branch_name: @start_branch)
      else
        s_("MergeRequests|Can't perform this action automatically. " \
          "It may have already been done, or a more recent commit may have updated some of this content. " \
          "Please perform this action locally.")
      end
    end
  end
end
