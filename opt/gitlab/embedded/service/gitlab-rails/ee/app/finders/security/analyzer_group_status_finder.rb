# frozen_string_literal: true

module Security
  class AnalyzerGroupStatusFinder
    include FinderMethods
    include Gitlab::Utils::StrongMemoize

    extend ::Gitlab::Utils::Override

    def initialize(group = nil, params = {})
      @group = group
      @params = params
    end

    def execute
      statuses = Security::AnalyzerNamespaceStatus.by_namespace(group).to_a
      fill_in_missing_types(group, statuses)
    end

    private

    attr_reader :group, :params

    def fill_in_missing_types(group, statuses)
      covered_types = statuses.map(&:analyzer_type)
      enum_types = Enums::Security.analyzer_types.keys.map(&:to_s)

      (enum_types - covered_types).each do |type|
        statuses << Security::AnalyzerNamespaceStatus.new(
          analyzer_type: type,
          namespace_id: group.id,
          updated_at: Time.current)
      end

      statuses
    end
  end
end
