# frozen_string_literal: true

module Search
  module Elastic
    module Concerns
      module ReferenceUtils
        extend ActiveSupport::Concern

        def delimit(string)
          string.split(self::DELIMITER)
        end

        def join_delimited(array)
          array.join(self::DELIMITER)
        end

        def ref_klass(string)
          "#{ref_module}::#{delimit(string).first}".safe_constantize
        end

        def legacy_ref_klass
          "#{ref_module}::Legacy".constantize
        end

        def ref_module
          to_s.pluralize
        end

        def environment_specific_index_name(type)
          [Gitlab::CurrentSettings.elasticsearch_prefix, Rails.env, type].join('-')
        end
      end
    end
  end
end
