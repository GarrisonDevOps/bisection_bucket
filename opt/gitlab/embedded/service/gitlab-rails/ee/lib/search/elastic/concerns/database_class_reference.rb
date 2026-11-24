# frozen_string_literal: true

module Search
  module Elastic
    module Concerns
      module DatabaseClassReference
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        BATCH_SIZE = Search::Elastic::Reference::PRELOAD_BATCH_SIZE

        override :preload_indexing_data
        def preload_indexing_data(refs)
          refs.group_by(&:model_klass).each do |klass, group|
            group.each_slice(BATCH_SIZE) do |batch|
              ids = batch.map(&:identifier)

              records = klass.id_in(ids).preload_indexing_data
              records_by_id = records.index_by(&:id)

              batch.each do |ref|
                ref.database_record = records_by_id[ref.identifier.to_i]
              end
            end
          end

          refs
        end
      end
    end
  end
end
