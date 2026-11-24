# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowLinksBaseResolver < BaseResolver # rubocop:disable Graphql/ResolverType -- abstract base; each subclass defines its own type
        include LooksAhead

        def resolve_with_lookahead(link_type: nil)
          association = self.class.links_association
          raise NotImplementedError, "#{self.class} must set `links_association`" unless association

          # rubocop:disable GitlabSecurity/PublicSend -- association is a static class attribute, not user input
          links = object.public_send(association)
          # rubocop:enable GitlabSecurity/PublicSend
          links = links.with_link_type(link_type) if link_type

          # Preload both sides of the join so the connection's `work_item` /
          # `workflow` fields don't N+1, and the workflow's own associations so its
          # per-session user / project / agent fields don't either. The artifact side
          # is whichever association the concrete join model wired up via `links_workflow_to`.
          # rubocop:disable CodeReuse/ActiveRecord -- generic join preload to avoid N+1 on the link's sides
          apply_lookahead(links.preload(
            links.klass.workflow_artifact_association,
            workflow: [:project, :user, :namespace, { ai_catalog_item_version: :item }]
          ))
          # rubocop:enable CodeReuse/ActiveRecord
        end

        class << self
          attr_accessor :links_association

          # Assigning the enum also declares the shared `link_type` filter
          # argument, so each concrete resolver only names its enum once
          # (alongside `links_association`) instead of repeating the argument.
          def link_type_enum=(enum)
            raise ArgumentError, "link_type_enum already set on #{self}" if @link_type_enum

            @link_type_enum = enum

            argument :link_type, enum,
              required: false,
              description: 'Filter links by their link type.'
          end
        end
      end
    end
  end
end
