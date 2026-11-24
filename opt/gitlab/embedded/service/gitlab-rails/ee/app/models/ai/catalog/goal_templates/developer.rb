# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer < Base
        def self.resolve(event_type:, resource:, user_input:, params: {})
          raise ArgumentError, 'resource must not be nil' unless resource

          handler = handler_for(event_type, resource, params)
          interpolate(handler.template, vars: handler.vars(resource: resource, params: params), user_input: user_input)
        end

        def self.handler_for(event_type, resource, params = {})
          case event_type
          when :init_execution_env   then Developer::InitExecutionEnv
          when :mention              then Developer::Mention
          when :assign_reviewer      then Developer::AssignMergeRequestReview
          when :merge_request_code_conflict then Developer::MergeConflict
          when :merge_request
            # Only `merged`, `pipeline_failed` and `requested_changes` have a Developer template. Other merge_request
            # actions (for example `approved`, dispatched by ExecuteMergeRequestApprovedWorkflowTriggersWorker) must
            # not silently fall through to another template and tell the agent the wrong thing.
            case params[:action].to_s
            when 'merged' then Developer::MergedMergeRequest
            when 'pipeline_failed' then Developer::FailedPipeline
            when 'requested_changes' then Developer::RequestedChanges
            else
              raise UnsupportedEventError,
                "Unsupported merge request action for Developer goal template: #{params[:action].inspect}"
            end
          when :work_item
            # Only `status_changed` has a Developer template; there is no goal for
            # `created` yet, so fail loudly rather than guessing one.
            return Developer::ImplementWorkItem if params[:action].to_s == 'status_changed'

            raise UnsupportedEventError,
              "Unsupported work item action for Developer goal template: #{params[:action].inspect}"
          when :assign
            resource.is_a?(MergeRequest) ? Developer::AssignMergeRequest : Developer::ImplementWorkItem
          else
            raise UnsupportedEventError, "Unsupported event type for Developer goal template: #{event_type.inspect}"
          end
        end

        def self.resource_display_name(resource)
          case resource
          when MergeRequest then 'merge request'
          when WorkItem then 'work item'
          when Issue then 'issue'
          else resource.class.name.demodulize.underscore.humanize(capitalize: false)
          end
        end
      end
    end
  end
end
