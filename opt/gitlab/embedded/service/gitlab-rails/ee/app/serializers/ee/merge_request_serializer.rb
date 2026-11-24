# frozen_string_literal: true

module EE
  module MergeRequestSerializer
    extend ::Gitlab::Utils::Override

    override :identified_entity
    def identified_entity(opts)
      if opts[:serializer] == 'ai'
        MergeRequestAiEntity
      elsif opts[:serializer] == 'sidebar'
        ::MergeRequests::SidebarBasicEntity
      else
        super(opts)
      end
    end
  end
end
