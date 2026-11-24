# frozen_string_literal: true

module Ai
  module Messaging
    module Adapters
      class Slack < Base
        # Says which setting refused a mention and who can change it. nil keeps the adapter's own reply.
        module DuoGroupReplies
          extend self

          def text(error, ctx)
            case error
            when :duo_group_not_set_up then not_set_up(ctx)
            when :duo_group_experiments_off then experiments_off(ctx)
            when :cannot_create_workflow_pipeline then refused(ctx)
            when :usage_quota_exceeded, :usage_billing_forbidden then no_credits(ctx)
            when :flow_disabled_by_feature_flag
              s_("DuoSlack|GitLab Duo in Slack isn't available for this Slack workspace yet.")
            end
          end

          private

          def not_set_up(ctx)
            if ctx['setup_by'] == 'admin'
              format(s_("DuoSlack|GitLab Duo is off for this Slack workspace. Your GitLab administrator " \
                "can turn it on in the Admin area: %{url}"), url: ctx['setup_url'])
            else
              s_("DuoSlack|GitLab Duo is off for this Slack workspace. An Owner of a top-level group can turn " \
                "it on by installing the GitLab for Slack app on that group, or in the app's settings if it's " \
                "already installed there.")
            end
          end

          def experiments_off(ctx)
            if ctx['settings_by_admin']
              s_("DuoSlack|GitLab Duo in Slack is an experiment. Your GitLab administrator can turn on " \
                "experiment and beta features for the instance.")
            else
              with_group(ctx,
                s_("DuoSlack|GitLab Duo in Slack is an experiment. An Owner of %{group} can turn on " \
                  "experiment and beta features in the group's GitLab Duo settings."),
                s_("DuoSlack|GitLab Duo in Slack is an experiment. An Owner of the group it runs in can " \
                  "turn on experiment and beta features in the group's GitLab Duo settings."))
            end
          end

          def refused(ctx)
            case ctx['duo_group_refusal']
            when 'duo_features_off'
              with_group(ctx,
                s_("DuoSlack|GitLab Duo is turned off in %{group}. An Owner of %{group} can turn it on " \
                  "in the group's GitLab Duo settings."),
                s_("DuoSlack|GitLab Duo is turned off in the group it runs in for this Slack workspace. " \
                  "Ask an Owner of that group to turn it on."))
            when 'agent_platform_off'
              agent_platform_off(ctx)
            when 'not_licensed'
              with_group(ctx,
                s_("DuoSlack|GitLab Duo Agent Platform isn't available in %{group}. An Owner of %{group} " \
                  "can check the group's GitLab Duo subscription."),
                s_("DuoSlack|GitLab Duo Agent Platform isn't available in the group it runs in for this " \
                  "Slack workspace. Ask an Owner of that group to check its GitLab Duo subscription."))
            when 'seat'
              with_group(ctx,
                s_("DuoSlack|You don't have access to GitLab Duo Agent Platform in %{group}. " \
                  "Ask an Owner of %{group} for access."),
                s_("DuoSlack|You don't have access to GitLab Duo Agent Platform in the group it runs in " \
                  "for this Slack workspace. Ask an Owner of that group for access."))
            else
              with_group(ctx,
                s_("DuoSlack|GitLab Duo for this Slack workspace runs in %{group}. You don't have the role " \
                  "%{group} requires for GitLab Duo. Ask an Owner of %{group} for access, then mention me again."),
                s_("DuoSlack|GitLab Duo for this Slack workspace runs in a group where you don't have the " \
                  "role it requires for GitLab Duo. Ask an Owner of that group for access."))
            end
          end

          def agent_platform_off(ctx)
            if ctx['settings_by_admin']
              s_("DuoSlack|GitLab Duo Agent Platform is turned off for this instance. " \
                "Your GitLab administrator can turn it on.")
            else
              with_group(ctx,
                s_("DuoSlack|GitLab Duo Agent Platform is turned off in %{group}. An Owner of %{group} " \
                  "can turn it on in the group's GitLab Duo settings."),
                s_("DuoSlack|GitLab Duo Agent Platform is turned off in the group it runs in for this " \
                  "Slack workspace. Ask an Owner of that group to turn it on."))
            end
          end

          def no_credits(ctx)
            with_group(ctx,
              s_("DuoSlack|GitLab Duo for this Slack workspace has no credits left in %{group}. " \
                "Ask an Owner of %{group} to check its GitLab Duo usage."),
              s_("DuoSlack|GitLab Duo for this Slack workspace has no credits left. " \
                "Ask an Owner of the group it runs in to check its GitLab Duo usage."))
          end

          # A private group's name must not reach someone who can't see it.
          def with_group(ctx, named, unnamed)
            name = ctx['duo_group_name']
            name.present? ? format(named, group: name) : unnamed
          end
        end
      end
    end
  end
end
