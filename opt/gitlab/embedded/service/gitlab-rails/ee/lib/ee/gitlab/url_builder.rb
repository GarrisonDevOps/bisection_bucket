# frozen_string_literal: true

module EE
  module Gitlab
    module UrlBuilder
      extend ActiveSupport::Concern

      class_methods do
        extend ::Gitlab::Utils::Override

        override :build
        def build(object, **options)
          case object.itself
          when ::Epic
            instance.group_epic_url(object.group, object, **options)
          when ::Boards::EpicBoard
            instance.group_epic_board_url(object.group, object, **options)
          when ::Iteration
            instance.iteration_url(object, **options)
          when ::Vulnerability
            instance.project_security_vulnerability_url(object.project, object, **options)
          when ::Vulnerabilities::RelatedIssuesDecorator
            instance.issue_url(object, **options)
          when ::ComplianceManagement::Projects::ComplianceViolation
            instance.project_security_compliance_violation_url(object.project, object, **options)
          when ::Ai::Catalog::Item
            ai_catalog_item_url(object, **options)
          when ::Ai::DuoWorkflows::Workflow
            duo_workflow_url(object, **options)
          when ::WorkItems::Decision
            decision_url(object, **options)
          else
            super
          end
        end

        def duo_workflow_url(workflow, **options)
          return unless workflow.id

          if workflow.project_level?
            instance.project_automate_agent_session_url(workflow.project, workflow.id, **options)
          elsif workflow.namespace.is_a?(::Group)
            root = workflow.namespace.root_ancestor
            return unless root

            # The group agent platform page is only served on top-level groups.
            instance.group_automate_agent_session_url(root, workflow.id, **options)
          end
        end

        # Must match the URL the frontend "Copy link" action builds: `show` opens
        # the decision log panel, the anchor scrolls to the card
        def decision_url(decision, **options)
          build(decision.work_item, show: 'decision-log', anchor: "decision_#{decision.id}", **options)
        end

        def ai_catalog_item_url(item, **options)
          return unless item.id

          item_type_path = case item.item_type.to_sym
                           when ::Ai::Catalog::Item::AGENT_TYPE, ::Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE
                             'agents'
                           when ::Ai::Catalog::Item::FLOW_TYPE
                             'flows'
                           when ::Ai::Catalog::Item::SKILL_TYPE
                             'skills'
                           end

          base_path = instance.explore_ai_catalog_path
          path = "#{base_path}/#{item_type_path}/#{item.id}"

          return path if options[:only_path]

          ::Gitlab::Utils.append_path(::Gitlab.config.gitlab.url, path)
        end

        override :note_url
        def note_url(note, **options)
          noteable = note.noteable

          if note.for_epic?
            instance.work_item_url(noteable, anchor: dom_id(note), **options)
          elsif note.for_vulnerability?
            instance.project_security_vulnerability_url(noteable.project, noteable, anchor: dom_id(note), **options)
          elsif note.for_group_wiki?
            instance.group_wiki_page_url(note.noteable, anchor: dom_id(note), **options)
          elsif note.for_compliance_violation?
            instance.project_security_compliance_violation_url(
              noteable.project, noteable, anchor: dom_id(note), **options)
          else
            super
          end
        end

        override :wiki_url
        def wiki_url(wiki, **options)
          if wiki.container.is_a?(Group)
            options[:controller] = 'groups/wikis'
            options[:group_id] = wiki.container
          end

          super
        end
      end
    end
  end
end
