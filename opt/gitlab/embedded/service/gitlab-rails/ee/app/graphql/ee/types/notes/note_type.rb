# frozen_string_literal: true

module EE
  module Types
    module Notes
      module NoteType
        extend ActiveSupport::Concern

        prepended do
          field :duo_workflow_links,
            resolver: ::Resolvers::Ai::DuoWorkflows::NoteDuoWorkflowLinksResolver,
            description: 'GitLab Duo Agent Platform sessions linked to the note.' do
              extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
            end

          field :duo_triggered_session,
            ::Types::Ai::DuoWorkflows::WorkflowType,
            null: true,
            directives: granular_scope_directive(
              permissions: :read_duo_workflow, boundary: :user, boundary_type: :user
            ),
            description: 'Duo Agent Platform session triggered by the note. ' \
              'Returns nil for system notes or when no triggered session exists.'

          field :duo_created_session, ::Types::Ai::DuoWorkflows::WorkflowType,
            null: true,
            directives: granular_scope_directive(
              permissions: :read_duo_workflow, boundary: :user, boundary_type: :user
            ),
            description: 'GitLab Duo Agent Platform session that created the note.'

          field :agent_presence, ::Types::Ai::DuoWorkflows::AgentPresenceType,
            null: true,
            experiment: { milestone: '19.5' },
            description: 'Agent attribution for a note posted by a GitLab Duo Agent Platform session. ' \
              'Available to anyone who can read the note; `userPermissions.readDuoWorkflow` tells whether ' \
              'the session itself can be opened. Returns null for system notes, when no session posted the note, ' \
              'or when the `agent_presence_consolidation` feature flag is disabled.'
        end

        def duo_triggered_session
          return if object.system?

          BatchLoader::GraphQL.for(object.id).batch(key: :duo_triggered_session) do |note_ids, loader|
            links = ::Ai::DuoWorkflows::WorkflowNote.triggered_for_notes_order_by_id_desc(note_ids)

            resolved = {}
            links.each do |link|
              next if resolved.key?(link.note_id)

              # Record the newest link first so older links cannot be used as fallbacks
              # if the newest workflow is unauthorized.
              resolved[link.note_id] = nil

              workflow = link.workflow
              next unless workflow
              next unless Ability.allowed?(current_user, :read_duo_workflow, workflow)

              resolved[link.note_id] = workflow
            end

            note_ids.each { |id| loader.call(id, resolved[id]) }
          end
        end

        def duo_created_session
          return unless current_user

          BatchLoader::GraphQL.for(object.id).batch(key: current_user) do |note_ids, loader, args|
            user = args[:key]
            created = ::Ai::DuoWorkflows::WorkflowNote.created_for_notes_order_by_id_asc(note_ids).preload_workflow.group_by(&:note_id)

            note_ids.each do |id|
              workflow = created[id]&.first&.workflow
              readable = workflow && Ability.allowed?(user, :read_duo_workflow, workflow)

              loader.call(id, readable ? workflow : nil)
            end
          end
        end

        def agent_presence
          return if object.system?

          actor = agent_presence_flag_actor
          return unless actor && ::Feature.enabled?(:agent_presence_consolidation, actor)

          BatchLoader::GraphQL.for(object.id).batch do |note_ids, loader|
            workflows = agent_presence_workflows(note_ids)

            note_ids.each { |id| loader.call(id, workflows[id]) }
          end
        end

        private

        # Deliberately not Note#resource_parent: that goes through #noteable, which hits Gitaly for commit notes.
        def agent_presence_flag_actor
          (object.project || object.namespace)&.root_ancestor
        end

        # duo_metadata takes precedence over the created link, matching EE::NoteEntity:
        # Code Review notes published before !260150 only have duo_metadata.
        def agent_presence_workflows(note_ids)
          workflow_id_by_note = ::Notes::NoteDuoMetadata.primary_key_in(note_ids).to_h do |metadata|
            [metadata.note_id, metadata.workflow_id]
          end

          ::Ai::DuoWorkflows::WorkflowNote.created_for_notes_order_by_id_asc(note_ids).each do |link|
            workflow_id_by_note[link.note_id] ||= link.workflow_id
          end

          workflows = ::Ai::DuoWorkflows::Workflow.id_in(workflow_id_by_note.values.uniq)
            .with_preloaded_associations.index_by(&:id)

          workflow_id_by_note.transform_values { |workflow_id| workflows[workflow_id] }
        end
      end
    end
  end
end
