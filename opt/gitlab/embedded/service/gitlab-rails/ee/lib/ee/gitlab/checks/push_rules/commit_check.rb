# frozen_string_literal: true

module EE
  module Gitlab
    module Checks
      module PushRules
        class CommitCheck < ::Gitlab::Checks::BaseSingleChecker
          ERROR_MESSAGES = {
            committer_not_verified: "Committer email '%{committer_email}' is not verified.",
            committer_not_allowed: "You cannot push commits for '%{committer_email}'. You can only push commits if the committer email is one of your own verified emails."
          }.freeze

          LOG_MESSAGE = "Checking if commits follow defined push rules..."

          def validate!
            return unless push_rule

            commit_validation = push_rule.commit_validation?
            # if newrev is blank, the branch was deleted
            return if deletion? || !commit_validation

            logger.log_timed(LOG_MESSAGE) do
              commits.each do |commit|
                logger.check_timeout_reached

                push_rule_commit_check(commit)
              end
            end
          rescue ::PushRule::MatchError => e
            raise ::Gitlab::GitAccess::ForbiddenError, e.message
          end

          private

          def push_rule_commit_check(commit)
            error = check_commit(commit)
            raise ::Gitlab::GitAccess::ForbiddenError, error if error
          end

          # If commit does not pass push rule validation the whole push should be rejected.
          # This method should return nil if no error found or a string if error.
          # In case of errors - all other checks will be canceled and push will be rejected.
          def check_commit(commit)
            unless push_rule.commit_message_allowed?(commit.safe_message)
              return "Commit message does not follow the pattern '#{push_rule.commit_message_regex}'"
            end

            if push_rule.commit_message_blocked?(commit.safe_message)
              return "Commit message contains the forbidden pattern '#{push_rule.commit_message_negative_regex}'"
            end

            # Historically, when a commit is created via Web UI, the committer and author emails are the same
            # It changes with https://gitlab.com/gitlab-org/gitaly/-/issues/5715 issue and now the committer email
            # of the commits created by Gitaly has an instance email like <noreply@gitlab.com>
            if !signed_by_gitlab?(commit) && !push_rule.author_email_allowed?(commit.committer_email)
              return "Committer's email '#{commit.committer_email}' does not follow the pattern '#{push_rule.author_email_regex}'"
            end

            unless push_rule.author_email_allowed?(commit.author_email)
              return "Author's email '#{commit.author_email}' does not follow the pattern '#{push_rule.author_email_regex}'"
            end

            committer_error_message = committer_check(commit)
            return committer_error_message if committer_error_message

            unless push_rule.non_dco_commit_allowed?(commit.safe_message)
              return "Commit message must contain a DCO signoff"
            end

            return "Commit must be signed" if !updated_from_web? && !push_rule.commit_signature_allowed?(commit)

            # Check whether author is a GitLab member
            member_error_message = check_member(commit)
            return member_error_message if member_error_message

            nil
          end

          def check_member(commit)
            return unless push_rule.member_check

            # Author membership is enforced for all commits, including instance-signed
            # ones - a system signature proves GitLab created the commit, not that the
            # named author is a member.
            unless ::User.find_by_any_email(commit.author_email).present?
              return "Author '#{commit.author_email}' is not a member of team"
            end

            # The committer of an instance-signed commit is GitLab itself
            # (noreply@<instance>), so there is no committer membership to verify.
            return if signed_by_gitlab?(commit)

            if commit.author_email.casecmp(commit.committer_email) != 0
              unless ::User.find_by_any_email(commit.committer_email).present?
                "Committer '#{commit.committer_email}' is not a member of team"
              end
            end
          end

          def committer_check(commit)
            if signed_by_gitlab?(commit)
              # Non-web (e.g. mirroring): the committer is GitLab itself
              # (noreply@<instance>); there is nothing to verify against the pusher.
              return unless updated_from_web?

              # Web: the committer email is the instance email per
              # https://gitlab.com/gitlab-org/gitaly/-/issues/5715, so verify the
              # author email instead - the author is the acting user.
              committer_email = commit.author_email
            else
              committer_email = commit.committer_email
            end

            unless push_rule.committer_allowed?(committer_email, user_access.user)
              # We can assume only one user holds an unconfirmed primary email address. Since we want
              # to give feedback whether this is an unconfirmed address, we look for any user that
              # matches by disabling the confirmation requirement.
              committer = commit.committer(confirmed: false)
              committer_is_current_user = committer == user_access.user

              if committer_is_current_user && !committer.verified_email?(committer_email)
                return ERROR_MESSAGES[:committer_not_verified] % { committer_email: committer_email }
              else
                return ERROR_MESSAGES[:committer_not_allowed] % { committer_email: committer_email }
              end
            end

            if commit.committer_email == commit.author_email && !push_rule.committer_name_allowed?(commit.author_name, user_access.user)
              "Your git author name is inconsistent with GitLab account name"
            end
          end
        end
      end
    end
  end
end
