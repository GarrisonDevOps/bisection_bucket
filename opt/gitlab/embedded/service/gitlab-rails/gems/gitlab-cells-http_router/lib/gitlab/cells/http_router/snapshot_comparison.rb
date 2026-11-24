# frozen_string_literal: true

require "json"

module Gitlab
  module Cells
    module HttpRouter
      # Checks that the HTTP Router's copy of the routing snapshot has every
      # route a branch adds or changes, compared with the snapshot on its target.
      #
      # Routes that only the router has do not count. Other open merge requests
      # add their routes there too, and an extra route is the safe direction.
      class SnapshotComparison
        # A payload with fewer routes than this is a truncated response or an
        # error page rather than a snapshot. Real snapshots hold thousands.
        MIN_ROUTES = 1000

        # Carries the side that failed, so a caller can report a bad download
        # separately from a bad file on the branch.
        class InvalidSnapshotError < StandardError
          LABELS = {
            gitlab: "The GitLab snapshot",
            base: "The GitLab snapshot on the target branch",
            router: "The HTTP Router snapshot"
          }.freeze

          attr_reader :source

          def initialize(source, message)
            @source = source

            super("#{LABELS.fetch(source)} #{message}")
          end
        end

        # Raises InvalidSnapshotError rather than returning a comparison, so a
        # caller can report a bad download separately from route drift. Reporting
        # them the same way would let a 404 HTML page read as wholesale drift.
        #
        # @return [Hash{String => Hash}] each route entry, keyed by its template
        def self.parse(payload, source:)
          routes = begin
            JSON.parse(payload)
          rescue JSON::ParserError => e
            raise InvalidSnapshotError.new(source, "is not valid JSON: #{e.message}")
          end

          unless routes.is_a?(Array)
            raise InvalidSnapshotError.new(source, "is #{routes.class}, expected an array of routes")
          end

          if routes.size < MIN_ROUTES
            raise InvalidSnapshotError.new(source,
              "holds only #{routes.size} routes, expected at least #{MIN_ROUTES}")
          end

          templates = routes.map { |route| route["template"] if route.is_a?(Hash) }

          if templates.any? { |template| !template.is_a?(String) || template.empty? }
            raise InvalidSnapshotError.new(source, "has an entry without a template")
          end

          # Entries are keyed by template, so a duplicate would hide one of them.
          duplicate = templates.tally.find { |_template, count| count > 1 }&.first
          raise InvalidSnapshotError.new(source, "has a duplicate template: #{duplicate}") if duplicate

          templates.zip(routes).to_h
        end

        # missing: templates the branch adds or changes that the router does not have.
        # outdated: templates the branch adds or changes that the router has with other fields.
        attr_reader :missing, :outdated

        # Each argument is the raw file contents. The whole entry is compared, so
        # a change to `acceptsFormat` or `dottedExample` counts as a change.
        def initialize(gitlab_payload:, base_payload:, router_payload:)
          gitlab_routes = self.class.parse(gitlab_payload, source: :gitlab)
          base_routes = self.class.parse(base_payload, source: :base)
          router_routes = self.class.parse(router_payload, source: :router)

          @missing, @outdated = gitlab_routes
            .reject { |template, route| base_routes[template] == route || router_routes[template] == route }
            .keys
            .sort
            .partition { |template| !router_routes.key?(template) }
        end

        def in_sync?
          missing.empty? && outdated.empty?
        end
      end
    end
  end
end
