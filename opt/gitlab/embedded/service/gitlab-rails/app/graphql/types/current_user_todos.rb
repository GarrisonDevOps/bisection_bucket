# frozen_string_literal: true

# Interface to expose todos for the current_user on the `object`
module Types
  module CurrentUserTodos
    include BaseInterface

    field_class Types::BaseField

    field :current_user_todos, Types::TodoType.connection_type,
      description: 'To-do items for the current user.',
      null: false,
      scopes: [:api, :read_api, :ai_workflows] do
      argument :state, Types::TodoStateEnum,
        description: 'State of the to-do items.',
        required: false
      argument :note_id, ::Types::GlobalIDType[::Note],
        description: 'Global ID of a comment. Returns only the to-do items for the comment.',
        required: false,
        experiment: { milestone: '19.6' }
    end

    def current_user_todos(state: nil, note_id: nil)
      state ||= %i[done pending] # TodosFinder treats a `nil` state param as `pending`
      target_type_name = unpresented.try(:todoable_target_type_name) || unpresented.class.name
      key = [state, target_type_name, note_id&.model_id]

      BatchLoader::GraphQL.for(unpresented).batch(default_value: [], key: key) do |targets, loader, args|
        state, klass_name, note_id = args[:key]

        targets_by_id = targets.index_by(&:id)
        ids = targets_by_id.keys

        results = TodosFinder.new(users: current_user, state: state, type: klass_name, target_id: ids).execute
        results = note_id ? results.for_note(note_id) : results.with_preloaded_note

        by_target_id = results.group_by(&:target_id)

        by_target_id.each do |target_id, todos|
          target = targets_by_id[target_id]
          todos.each { _1.target = target } # prevent extra loads
          loader.call(target, todos)
        end
      end
    end
  end
end
