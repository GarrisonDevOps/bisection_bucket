# frozen_string_literal: true

module Types
  module Boards
    class EpicListType < BaseObject
      graphql_name 'EpicList'
      description 'Represents an epic board list'

      include Gitlab::Utils::StrongMemoize

      accepts ::Boards::EpicList
      authorize :read_epic_board_list

      alias_method :list, :object

      field :id,
        type: ::Types::GlobalIDType[::Boards::EpicList],
        null: false, description: 'Global ID of the board list.'

      field :title, GraphQL::Types::String, null: false, description: 'Title of the list.'

      field :list_type, GraphQL::Types::String, null: false, description: 'Type of the list.'

      field :position, GraphQL::Types::Int,
        null: true, description: 'Position of the list within the board.'

      field :label, Types::LabelType, null: true, description: 'Label of the list.'

      field :collapsed, GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates if the list is collapsed for the user.'

      field :epics, Types::EpicType.connection_type,
        null: true,
        resolver: Resolvers::Boards::BoardListEpicsResolver,
        description: 'List epics.'

      field :metadata, Types::Boards::EpicListMetadataType,
        null: true, extras: [:lookahead], description: 'Epic list metatada.'

      def collapsed
        object.collapsed?(current_user)
      end

      def metadata(lookahead: nil)
        required_metadata = []
        required_metadata << :epics_count if lookahead&.selects?(:epics_count)
        required_metadata << :total_weight if lookahead&.selects?(:total_weight)

        list_service.metadata(required_metadata)
      end

      def list_service
        ::Boards::Epics::ListService.new(list.epic_board.resource_parent, current_user, params)
      end

      def params
        (context[:epic_filters] || {}).merge(board: list.epic_board, list: list)
      end

      def title
        BatchLoader::GraphQL.for(object).batch do |lists, callback|
          ActiveRecord::Associations::Preloader.new(records: lists, associations: :label).call

          # all list titles are preloaded at this point
          lists.each { |list| callback.call(list, list.title) }
        end
      end
    end
  end
end
