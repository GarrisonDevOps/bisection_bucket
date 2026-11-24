# frozen_string_literal: true

# This patch provides a GitLab-specific override of `query_constraints` for
# partitioned models. Rails ships a native `query_constraints` in:
# https://github.com/rails/rails/blob/v8.0.0/activerecord/lib/active_record/persistence.rb#L212
#
# The GitLab version intentionally omits setting `@has_query_constraints` so
# that the standard ActiveRecord `_query_constraints_hash` is not used; instead
# the partitioning layer manages composite-key lookups itself.

if ::ActiveRecord::VERSION::STRING >= "8.2"
  raise 'New version of active-record detected, please remove or update this patch'
end

# rubocop:disable Gitlab/ModuleWithInstanceVariables
module ActiveRecord
  module GitlabPatches
    module Partitioning
      module Base
        module ClassMethods
          def query_constraints(*columns_list)
            raise ArgumentError, "You must specify at least one column to be used in querying" if columns_list.empty?

            @query_constraints_list = columns_list.map(&:to_s)
          end
        end
      end
    end
  end
end
# rubocop:enable Gitlab/ModuleWithInstanceVariables
