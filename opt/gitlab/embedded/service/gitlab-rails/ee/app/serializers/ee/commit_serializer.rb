# frozen_string_literal: true

module EE
  class CommitSerializer < BaseSerializer
    # This method takes care of which entity should be used
    # to serialize the `commit` based on `serializer` key in `opts` param.
    # Hence, `entity` doesn't need to be declared on the class scope.
    def represent(commit, opts = {})
      entity = choose_entity(opts)

      super(commit, opts, entity)
    end

    def choose_entity(opts)
      case opts[:serializer]
      when 'ai'
        CommitAiEntity
      else
        ::CommitEntity
      end
    end
  end
end
