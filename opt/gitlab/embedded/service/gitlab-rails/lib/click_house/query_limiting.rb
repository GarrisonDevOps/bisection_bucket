# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- existing module
  class QueryLimiting
    module NoLimit
      def self.type = 'none'
      def self.settings = {}
    end

    RULES = [
      ClickHouse::QueryLimiting::Rules::GuestWebRequest
    ].freeze

    def self.rule(context = Labkit::Context.current)
      RULES.find { |rule| rule.applies?(context) } || NoLimit
    end
  end
end
