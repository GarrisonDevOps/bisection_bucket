# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        # One goal for every event that asks the agent to implement a work item of any type.
        # An assignment and a status change differ only in who asked, not in the work.
        class ImplementWorkItem
          TEMPLATE = <<~GOAL.strip
            @%{triggered_by_username} asked you to solve the following %{resource_name}: %{resource_url}

            Fetch the details and understand the problem thoroughly before writing any code. If it is a bug, find the root cause. Otherwise, work out what the change requires. Either way, find where in the codebase the relevant logic lives. If there are multiple possible approaches, reason about the tradeoffs and pick the simplest one that fully addresses the %{resource_name}. Implement your solution, verify it works, then create a merge request with your changes.%{workplan_section}

            When you have completed your work, @mention @%{triggered_by_username} in a comment on the %{resource_name} to notify them. Assign @%{triggered_by_username} as the assignee of the merge request unless told differently.
          GOAL

          # A Workplan holds up to 128 KiB, twice the goal limit. These caps keep the inlined
          # Workplan plus the template under Workflow::GOAL_MAX_LENGTH and GOAL_MAX_BYTESIZE.
          # The Developer flow accepts no trigger goal, so the caps leave no room for one: if
          # it starts to accept one, lower them.
          WORKPLAN_INLINE_MAX_LENGTH = 60_000
          WORKPLAN_INLINE_MAX_BYTESIZE = 120.kilobytes
          WORKPLAN_TAG = %r{<\s*/?\s*workplan\s*>}i

          # The REST API does not return the Workplan. Variables keep the query a constant,
          # so the spec can validate it against the schema.
          WORKPLAN_QUERY = <<~GRAPHQL.squish
            query($fullPath: ID!, $iid: String!) {
              project(fullPath: $fullPath) {
                workItems(iid: $iid) { nodes { widgets { ... on WorkItemWidgetAgentPlan { content } } } }
              }
            }
          GRAPHQL

          def self.template
            TEMPLATE
          end

          def self.vars(resource:, params:, **_)
            resource_name = Developer.resource_display_name(resource)

            {
              resource_url: Gitlab::UrlBuilder.build(resource),
              resource_name: resource_name,
              triggered_by_username: params[:triggered_by_username].to_s,
              workplan_section: workplan_section(resource, resource_name)
            }
          end

          def self.workplan_section(resource, resource_name)
            content = strip_workplan_tags(workplan_content(resource))
            return '' if content.blank?

            if content.length <= WORKPLAN_INLINE_MAX_LENGTH && content.bytesize <= WORKPLAN_INLINE_MAX_BYTESIZE
              inline_workplan_section(content, resource_name)
            elsif resource.project
              fetch_workplan_section(resource, resource_name)
            else
              # The fetch query needs a project. Without one, the agent works from the details.
              ''
            end
          end

          def self.inline_workplan_section(content, resource_name)
            <<~SECTION.chomp.prepend("\n\n")
              The #{resource_name} has a Workplan, included below. #{follow_workplan(resource_name)}

              <workplan>
              #{content}
              </workplan>
            SECTION
          end

          def self.fetch_workplan_section(resource, resource_name)
            <<~SECTION.chomp.prepend("\n\n")
              The #{resource_name} has a Workplan that is too large to include here. Read it before you write any code. The REST API does not return the Workplan, so fetch it with this command:

              ```sh
              glab api graphql -f query='#{WORKPLAN_QUERY}' -f fullPath='#{resource.project.full_path}' -f iid='#{resource.iid}'
              ```

              #{follow_workplan(resource_name)}
            SECTION
          end

          def self.follow_workplan(resource_name)
            "Follow the Workplan as your implementation plan unless you find a good reason not to. " \
              "If you deviate from it, state each deviation and its reason in the merge request description. " \
              "The Workplan does not replace the #{resource_name} itself: still read its description and " \
              "comments for the product context you need to make good decisions while you implement. " \
              "If the description and the Workplan disagree, follow the Workplan, because it is the result " \
              "of planning."
          end

          # Reads through the widget, as GraphQL does, so the goal holds no Workplan that the UI
          # and the API hide: the widget applies the work item type, license and feature flag.
          def self.workplan_content(resource)
            work_item = resource.is_a?(::WorkItem) ? resource : ::WorkItem.find_by_id(resource.id)
            work_item&.get_widget(:agent_plan)&.content
          end

          # One pass, linear in the content. Each tag becomes a separator that WORKPLAN_TAG
          # cannot match, so the text around a tag cannot join into a new one:
          # <work<workplan>plan> becomes <work_plan>. A space would not work, because the
          # pattern allows whitespace inside a tag: <<workplan>workplan> would become
          # < workplan>.
          def self.strip_workplan_tags(text)
            text.to_s.gsub(WORKPLAN_TAG, '_')
          end

          private_class_method :workplan_section, :inline_workplan_section, :fetch_workplan_section,
            :follow_workplan, :workplan_content, :strip_workplan_tags
        end
      end
    end
  end
end
