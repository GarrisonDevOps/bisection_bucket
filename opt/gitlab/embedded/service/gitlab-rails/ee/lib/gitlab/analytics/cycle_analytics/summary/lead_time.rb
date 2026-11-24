# frozen_string_literal: true

module Gitlab
  module Analytics
    module CycleAnalytics
      module Summary
        class LeadTime < BaseTime
          def title
            _('Lead time')
          end

          def self.start_event_identifier
            :issue_created
          end

          def self.end_event_identifier
            :issue_closed
          end

          def count
            data_collector.count.to_i
          end

          def links
            helpers = Gitlab::Routing.url_helpers

            dashboard_link =
              if @stage.namespace.is_a?(::Group)
                helpers.group_issues_analytics_path(@stage.namespace, issues_analytics_params)
              else
                helpers.project_analytics_issues_analytics_path(@stage.namespace.project, issues_analytics_params)
              end

            [
              { "name" => _('Lead time'), "url" => dashboard_link, "label" => s_('ValueStreamAnalytics|Dashboard') },
              { "name" => _('Lead time'),
                "url" => helpers.help_page_path('user/analytics/_index.md', anchor: 'definitions'),
                "docs_link" => true,
                "label" => s_('ValueStreamAnalytics|Learn more') }
            ]
          end

          private

          def issues_analytics_params
            @options.slice(:author_username, :label_name, :milestone_title, :assignee_username).compact
          end
        end
      end
    end
  end
end
