# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class SystemDashboard
      include GlobalID::Identification

      attr_reader :slug, :config, :errors

      def initialize(slug:, config:, errors: [])
        @slug = slug
        @config = config
        @errors = errors
      end

      def id
        "gitlab:dashboard:#{slug}"
      end

      # A dashboard that failed schema validation may have no title; the GraphQL
      # name field is non-null, so the slug stands in.
      def name
        config['title'].presence || slug
      end

      def description
        config['description']
      end

      # Default only an absent key; `constraints: false` or a bare `constraints:` must reach the
      # policy as declared, so it is rejected instead of read as "no constraints".
      def constraints
        config.fetch('constraints', {})
      end

      def system?
        true
      end

      def readonly?
        true
      end

      def persisted?
        true
      end

      def created_at
        nil
      end
    end
  end
end
