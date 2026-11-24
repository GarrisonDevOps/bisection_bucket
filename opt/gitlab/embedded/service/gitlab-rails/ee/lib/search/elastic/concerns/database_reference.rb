# frozen_string_literal: true

module Search
  module Elastic
    module Concerns
      module DatabaseReference
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include Gitlab::Utils::StrongMemoize

        override :operation
        def operation
          database_record ? :index : :delete
        end

        override :database_record
        def database_record
          model_klass.find_by_id(identifier)
        end
        strong_memoize_attr :database_record

        def database_record=(record)
          strong_memoize(:database_record) { record }
        end

        override :database_id
        def database_id
          database_record&.id
        end

        def safely_read_attribute_for_elasticsearch(target, attr_name)
          result = target.send(attr_name) # rubocop: disable GitlabSecurity/PublicSend -- copied from previous definition
          apply_field_limit(result)
        rescue StandardError
        end

        def apply_field_limit(result)
          return result unless result.is_a? String

          limit = Gitlab::CurrentSettings.elasticsearch_indexed_field_length_limit

          return result unless limit > 0

          result[0, limit]
        end
      end
    end
  end
end
