# frozen_string_literal: true

module Gitlab
  module Encryption
    module DbKeyBaseRotation
      # A table with columns encrypted with a `db_key_base` key, and the model used to query it.
      class Table
        attr_reader :name, :model, :encrypted_columns

        # @param name [String] the table name
        # @param model [Class] the model whose connection reads and writes the table
        # @param encrypted_columns [Array<AttrEncryptedColumn, TokenColumn>] the encrypted columns
        def initialize(name, model, encrypted_columns)
          @name = name
          @model = model
          @encrypted_columns = encrypted_columns
        end

        # @return [Array<String>] every stored column of the encrypted columns
        def columns
          encrypted_columns.flat_map(&:columns)
        end

        # @return [Array<String>] the columns identifying a row: the model's primary key, then the rest of
        #   the table's primary key, which holds the partition key of a partitioned table so that writes are pruned
        def key_columns
          @key_columns ||= [model.primary_key, *(model.connection.primary_keys(name) - [model.primary_key])]
        end

        # @return [ActiveRecord::Relation] every row, ignoring default scopes
        def scope
          model.unscoped
        end

        # Narrows a batch to the rows worth re-encrypting, when the model defines
        # `db_key_base_reencryption_filter`.
        #
        # @param relation [ActiveRecord::Relation] a batch of the table's rows
        # @return [ActiveRecord::Relation]
        def filter(relation)
          return relation unless model.respond_to?(:db_key_base_reencryption_filter)

          model.db_key_base_reencryption_filter(relation)
        end
      end
    end
  end
end
