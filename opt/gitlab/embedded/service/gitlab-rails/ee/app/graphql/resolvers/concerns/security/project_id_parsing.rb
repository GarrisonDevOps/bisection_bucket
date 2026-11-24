# frozen_string_literal: true

module Security
  # Normalizes project identifiers into integer project IDs. Accepts both GID
  # format and raw numeric strings: the FE project token sends numeric IDs,
  # while GraphQL API consumers use the standard GID format.
  module ProjectIdParsing
    extend ActiveSupport::Concern

    private

    def parse_project_ids(ids)
      return unless ids.present?

      ids.filter_map do |id|
        GitlabSchema.parse_gid(id, expected_type: ::Project).model_id.to_i
      rescue Gitlab::Graphql::Errors::ArgumentError
        Integer(id, 10, exception: false)
      end
    end
  end
end
