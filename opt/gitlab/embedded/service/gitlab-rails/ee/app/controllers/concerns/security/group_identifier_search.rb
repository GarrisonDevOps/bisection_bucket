# frozen_string_literal: true

module Security
  # rubocop:disable Search/NamespacedClass -- not that kind of search
  module GroupIdentifierSearch
    MAX_VULNERABILITY_COUNT_GROUP_SUPPORT = 20_000

    private

    def search_by_identifier_allowed_on_db?(vulnerable:)
      return true if vulnerable.is_a?(::Project)
      return false unless vulnerable.is_a?(::Group)

      vulnerability_count = ::Security::ProjectStatistics.sum_vulnerability_count_for_group(vulnerable)
      vulnerability_count <= MAX_VULNERABILITY_COUNT_GROUP_SUPPORT
    end

    def search_by_identifier_allowed_on_db!(vulnerable:)
      return if search_by_identifier_allowed_on_db?(vulnerable: vulnerable)

      raise ::Gitlab::Graphql::Errors::ArgumentError,
        "#{vulnerable.type} has more than 20k vulnerabilities."
    end
  end
  # rubocop:enable Search/NamespacedClass
end
